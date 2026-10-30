"""`--apply-fixes` accounts for every fix, and agrees with the one-click paths.

A fix could vanish: an argument the file already had looked like one another
rule had just added, so it was neither applied nor listed. And the PR
suggestions decided separately, so they offered fixes the patcher refuses
and refused ones it applies.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DETECT = REPO / "scripts" / "detect.py"
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "tests"))

import detect
from _apply_fixes import (
    declared_names,
    fix_blocker,
    fix_refusal,
    handle_apply_fixes,
    undeclared_references,
    unindexed_references,
)


def _run(target: Path, *flags: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(target),
            "--no-threat-intel",
            "--no-suppress",
            *flags,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _catalog() -> dict:
    return {
        e["id"]: e for e in detect.load_catalog(Path(detect._default_catalog_dir()))
    }


def _counts(stderr: str) -> tuple[int, int, int]:
    applied = int(re.search(r"(?:applied|would apply) (\d+) fix", stderr).group(1))
    covered = re.search(r"(\d+) finding\(s\) covered", stderr)
    return (
        applied,
        stderr.count("apply-fixes: manual: "),
        int(covered.group(1)) if covered else 0,
    )


def _candidates(target: Path, catalog: dict) -> list[dict]:
    report = json.loads(_run(target, "--format", "json", "--show-info").stdout)
    return [
        f
        for f in report["findings"]
        if catalog.get(f["id"], {}).get("fix_hcl")
        or catalog.get(f["id"], {}).get("fix_hcl_minimal")
    ]


@pytest.mark.parametrize(
    "fixture",
    [
        "aws_s3_versioning_disabled_inline",
        "public_bucket",
        "int_intent_prod_deletion",
    ],
)
def test_named_fixtures_add_up(tmp_path, fixture) -> None:
    copy = tmp_path / fixture
    shutil.copytree(REPO / "fixtures" / fixture, copy)
    wanted = _candidates(copy, _catalog())
    applied, manual, covered = _counts(
        _run(copy, "--apply-fixes", "dry-run", "--format", "json").stderr
    )
    assert applied + manual + covered == len(wanted)


def test_every_fixture_adds_up(tmp_path) -> None:
    copy = tmp_path / "fixtures"
    shutil.copytree(REPO / "fixtures", copy)
    wanted = _candidates(copy, _catalog())
    applied, manual, covered = _counts(_run(copy, "--apply-fixes", "apply").stderr)
    assert applied + manual + covered == len(wanted)
    assert covered < applied


def test_an_argument_the_file_already_had_is_not_a_covered_fix(
    tmp_path, capsys
) -> None:
    (tmp_path / "main.tf").write_text(
        'resource "aws_x" "y" {\n  versioning {\n    enabled = false\n  }\n}\n'
    )
    entry = {
        "id": "X-Y-001",
        "fix_hcl": "versioning {\n  enabled = true\n}",
        "patterns": [
            {"kind": "resource_missing_arg", "resource": "aws_x", "arg": "versioning"}
        ],
    }
    finding = {
        "id": "X-Y-001",
        "file": str(tmp_path / "main.tf"),
        "line": 1,
        "resource": "aws_x.y",
    }
    handle_apply_fixes(None, [finding], [entry], dry_run=False)
    err = capsys.readouterr().err
    assert "manual: X-Y-001" in err and "covered" not in err


def test_two_rules_wanting_one_argument_are_one_fix_and_one_covered(
    tmp_path, capsys
) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_x" "y" {\n  name = "n"\n}\n')
    entries = [
        {
            "id": f"X-Y-00{i}",
            "fix_hcl": "days = 90",
            "patterns": [
                {"kind": "resource_missing_arg", "resource": "aws_x", "arg": "days"}
            ],
        }
        for i in (1, 2)
    ]
    findings = [
        {
            "id": e["id"],
            "file": str(tmp_path / "main.tf"),
            "line": 1,
            "resource": "aws_x.y",
        }
        for e in entries
    ]
    handle_apply_fixes(None, findings, entries, dry_run=False)
    err = capsys.readouterr().err
    assert (
        "applied 1 fix(es)" in err
        and "1 finding(s) covered" in err
        and "manual:" not in err
    )


# ---- count / for_each ----------------------------------------------------------


@pytest.mark.parametrize("meta", ["count = var.on ? 1 : 0", 'for_each = toset(["a"])'])
def test_a_fix_naming_an_instanced_resource_is_refused(tmp_path, meta) -> None:
    (tmp_path / "main.tf").write_text(
        'variable "on" {\n  type = bool\n}\n\n'
        f'resource "aws_kms_key" "logs" {{\n  {meta}\n}}\n\n'
        'resource "aws_cloudwatch_log_group" "lg" {\n  name = "x"\n}\n'
    )
    res = _run(tmp_path, "--apply-fixes", "apply")
    assert "kms_key_id" not in (tmp_path / "main.tf").read_text()
    assert "without an index" in res.stderr


def test_declared_names_marks_instances_only() -> None:
    names = declared_names(
        'resource "aws_a" "one" {\n  count = 2\n}\n'
        'resource "aws_a" "two" {\n  nested {\n    count = 2\n  }\n}\n'
        'module "m" {\n  source   = "./m"\n  for_each = var.x\n}\n'
        'data "aws_b" "d" {\n  for_each = var.x\n}\n'
    )
    assert names == {
        "aws_a.one",
        "aws_a.one[]",
        "aws_a.two",
        "module.m",
        "module.m[]",
        "data.aws_b.d",
        "data.aws_b.d[]",
    }


@pytest.mark.parametrize(
    "snippet, flagged",
    [
        ("a = aws_x.y.arn", ["aws_x.y"]),
        ("a = aws_x.y[0].arn", []),
        ("a = aws_x.y.*.arn", []),
        ('a = aws_x.y["k"].arn', []),
    ],
)
def test_unindexed_references(snippet, flagged) -> None:
    assert unindexed_references(snippet, {"aws_x.y", "aws_x.y[]"}) == flagged


# ---- fix_blocker's gaps ---------------------------------------------------------


@pytest.mark.parametrize(
    "snippet, missing",
    [
        ("a = <<EOT\nhello ${var.x}\nEOT\n", ["var.x"]),
        ('a = "%{ if var.x }y%{ endif }"', ["var.x"]),
        ("a = -var.x", ["var.x"]),
        ("a = 1 -var.x", ["var.x"]),
        ('a = "%%{ if var.x }"', []),
        ("a = <<EOT\n$${var.x}\nEOT\n", []),
        ("a = some-var.x", []),
    ],
)
def test_references_are_found_wherever_expressions_are(snippet, missing) -> None:
    assert undeclared_references(snippet, set()) == missing


@pytest.mark.parametrize(
    "snippet, block_args, blocked",
    [
        ("a = each.key", set(), True),
        ("a = each.key", {"for_each"}, False),
        ("a = count.index", set(), True),
        ("a = count.index", {"count"}, False),
        ("a = count.index", {"for_each"}, True),
        ('a = "${each.value}"', set(), True),
        ("a = each.key", None, False),
    ],
)
def test_each_and_count_need_their_meta_argument(snippet, block_args, blocked) -> None:
    assert bool(fix_blocker(snippet, set(), block_args)) is blocked


def test_the_patcher_uses_the_blocks_own_meta_arguments(tmp_path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_x" "y" {\n  name = "n"\n}\n')
    entry = {
        "id": "X-Y-001",
        "fix_hcl": "key = each.key",
        "patterns": [
            {"kind": "resource_missing_arg", "resource": "aws_x", "arg": "key"}
        ],
    }
    finding = {
        "id": "X-Y-001",
        "file": str(tmp_path / "main.tf"),
        "line": 1,
        "resource": "aws_x.y",
    }
    handle_apply_fixes(None, [finding], [entry], dry_run=False)
    assert "each.key" not in (tmp_path / "main.tf").read_text()


# ---- One decision, for the patcher and the one-click paths ------------------------


def test_a_nested_snippet_is_not_offered_either() -> None:
    catalog = _catalog()
    assert "nested block" in fix_refusal(
        catalog["STK-GCP-FUNCTIONS-002"],
        "google_cloudfunctions_function",
        {"google_service_account.fn"},
    )


def test_the_wrapper_of_a_patchable_fix_does_not_block_it() -> None:
    """`name = "example"` in the wrapper is never pasted."""
    entry = {
        "id": "X-Y-001",
        "fix_hcl": 'resource "aws_x" "y" {\n  name = "example"\n  a = 1\n}\n',
        "patterns": [{"kind": "resource_missing_arg", "resource": "aws_x", "arg": "a"}],
    }
    assert fix_refusal(entry, "aws_x", set()) is None


def test_a_rule_with_no_patch_is_judged_on_its_whole_fix() -> None:
    entry = {
        "id": "X-Y-001",
        "fix_hcl": 'resource "aws_x" "y" {\n  name = "example"\n}\n',
        "patterns": [{"kind": "grep", "regex": "x"}],
    }
    assert fix_refusal(entry, "aws_x", set())


def test_any_acceptable_pattern_is_enough() -> None:
    entry = {
        "id": "X-Y-001",
        "fix_hcl": "a = var.x\nb = 1\n",
        "patterns": [
            {"kind": "resource_missing_arg", "resource": "aws_x", "arg": "a"},
            {"kind": "resource_missing_arg", "resource": "aws_x", "arg": "b"},
        ],
    }
    assert fix_refusal(entry, "aws_x", set()) is None


_REFUSALS = ("references ", "holds the placeholder", "nested block", "examples")


def test_every_fixture_gets_the_same_answer_from_both_paths(tmp_path) -> None:
    copy = tmp_path / "fixtures"
    shutil.copytree(REPO / "fixtures", copy)
    report = json.loads(_run(copy, "--format", "json", "--show-info").stdout)
    err = _run(
        copy, "--apply-fixes", "dry-run", "--format", "json", "--show-info"
    ).stderr
    refused = {
        (m.group(1), m.group(2), int(m.group(3)))
        for m in re.finditer(r"manual: (\S+) (.+?):(\d+) \S+: (.*)", err)
        if any(word in m.group(4) for word in _REFUSALS)
    }
    annotated = {
        (f["id"], f["file"], f["line"])
        for f in report["findings"]
        if f.get("fix_manual_reason")
    }
    # A multi-pattern rule can be refused on one pattern's snippet and offered
    # on another's only when the arguments differ; both paths ask "any?".
    assert refused <= annotated, sorted(refused - annotated)[:10]


def test_most_patchable_fixes_stay_offered(tmp_path) -> None:
    """The wrapper check used to block 168 of 309 fixes the patcher makes."""
    copy = tmp_path / "fixtures"
    shutil.copytree(REPO / "fixtures", copy)
    report = json.loads(_run(copy, "--format", "json").stdout)
    err = _run(copy, "--apply-fixes", "dry-run", "--format", "json").stderr
    left = {(m[0], m[1]) for m in re.findall(r"manual: (\S+) (.+?):\d+ ", err)}
    done = [
        f
        for f in report["findings"]
        if f.get("fix_hcl") and (f["id"], f["file"]) not in left
    ]
    assert done
    assert not [f["id"] for f in done if f.get("fix_manual_reason")]


def test_the_quick_fix_is_not_offered_for_a_refused_fix(tmp_path) -> None:
    from test_lsp_server import LspClient, _file_uri, _initialize

    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_cloudwatch_log_group" "lg" {\n  name = "x"\n}\n')
    with LspClient() as lsp:
        _initialize(lsp)
        uri = _file_uri(tf)
        lsp.send_notification(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": uri,
                    "languageId": "terraform",
                    "version": 1,
                    "text": tf.read_text(),
                }
            },
        )
        msg = lsp.read_until(
            lambda m: (
                m.get("method") == "textDocument/publishDiagnostics"
                and m.get("params", {}).get("uri") == uri
            ),
            timeout=10.0,
        )
        diags = msg["params"]["diagnostics"]
        rid = lsp.send_request(
            "textDocument/codeAction",
            {
                "textDocument": {"uri": uri},
                "range": {
                    "start": {"line": 0, "character": 0},
                    "end": {"line": 0, "character": 0},
                },
                "context": {"diagnostics": diags},
            },
        )
        titles = [a["title"] for a in lsp.read_response(rid, timeout=10.0)["result"]]
    assert "tf-analyze fix: OPS-AWS-CWL-001" in titles
    assert "tf-analyze fix: SEC-AWS-CWL-001" not in titles
