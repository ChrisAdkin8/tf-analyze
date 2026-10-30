"""`--apply-fixes` must not paste what can't work, and must say what it left.

Fix snippets name things like `aws_kms_key.logs` and example values. Pasted
into a module that declares no such key, the fix turned a valid configuration
into one `terraform validate` rejects, and the run reported success.
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
sys.path.insert(0, str(REPO / "integrations" / "github-action-bot"))

import detect
from _apply_fixes import (
    annotate_fix_blockers,
    declared_names,
    fix_block_for_nested_arg,
    fix_blocker,
    fix_line_for_arg,
    placeholder_values,
    undeclared_references,
)

LOG_GROUP = 'provider "aws" {\n  region = "eu-west-1"\n}\n\nresource "aws_cloudwatch_log_group" "lg" {\n  name = "x"\n}\n'
SQS = 'resource "aws_sqs_queue" "q" {\n  name = "q"\n}\n'
KEY = 'resource "aws_kms_key" "logs" {\n  description = "logs"\n}\n'


def _catalog() -> list[dict]:
    return detect.load_catalog(Path(detect._default_catalog_dir()))


def _apply(
    target: Path, *flags: str, mode: str = "apply"
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(target),
            "--apply-fixes",
            mode,
            "--no-threat-intel",
            *flags,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_fix_naming_an_undeclared_resource_is_left_out_and_listed(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(LOG_GROUP)
    res = _apply(tmp_path)
    text = (tmp_path / "main.tf").read_text()
    assert "aws_kms_key" not in text
    assert "retention_in_days" in text
    assert "applied 1 fix(es) across 1 file(s)" in res.stderr
    assert re.search(
        r"# apply-fixes: manual: SEC-AWS-CWL-001 \S+main\.tf:5 aws_cloudwatch_log_group\.lg: "
        r"references aws_kms_key\.logs, not declared",
        res.stderr,
    )


def test_a_fix_another_rule_already_made_is_not_listed_as_left_over(tmp_path) -> None:
    """COST-AWS-RISK-001 and OPS-AWS-CWL-001 both want `retention_in_days`."""
    (tmp_path / "main.tf").write_text(LOG_GROUP)
    res = _apply(tmp_path)
    assert "retention_in_days" in (tmp_path / "main.tf").read_text()
    assert "manual: OPS-AWS-CWL-001" not in res.stderr
    assert "manual: COST-AWS-RISK-001" not in res.stderr


def test_a_fix_for_a_nested_block_is_not_pasted_at_the_top(tmp_path) -> None:
    """`encryption_option` means nothing directly under the workgroup."""
    (tmp_path / "main.tf").write_text(
        'resource "aws_athena_workgroup" "w" {\n  name = "w"\n}\n'
    )
    res = _apply(tmp_path)
    assert "encryption_option" not in (tmp_path / "main.tf").read_text()
    assert re.search(r"manual: SEC-AWS-ATHENA-001 .*nested block", res.stderr)


def test_dry_run_shows_the_same_as_a_real_run(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(LOG_GROUP)
    res = _apply(tmp_path, mode="dry-run")
    assert "aws_kms_key" not in res.stdout
    assert "would apply 1 fix(es) across 1 file(s)" in res.stderr
    assert "manual: SEC-AWS-CWL-001" in res.stderr
    assert (tmp_path / "main.tf").read_text() == LOG_GROUP


def test_the_sqs_case(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(SQS)
    res = _apply(tmp_path)
    assert "aws_kms_key" not in (tmp_path / "main.tf").read_text()
    assert "manual: SEC-AWS-SQS-001" in res.stderr


def test_a_declaration_in_a_sibling_file_lets_the_fix_through(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(LOG_GROUP)
    (tmp_path / "kms.tf").write_text(KEY)
    res = _apply(tmp_path)
    assert "aws_kms_key.logs.arn" in (tmp_path / "main.tf").read_text()
    assert "manual: SEC-AWS-CWL-001" not in res.stderr


def test_a_declaration_in_a_json_sibling_counts(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(LOG_GROUP)
    (tmp_path / "kms.tf.json").write_text(
        json.dumps({"resource": {"aws_kms_key": {"logs": {"description": "logs"}}}})
    )
    _apply(tmp_path)
    assert "kms_key_id" in (tmp_path / "main.tf").read_text()


def test_a_commented_out_declaration_does_not_count(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(
        LOG_GROUP + '# resource "aws_kms_key" "logs" {}\n'
    )
    _apply(tmp_path)
    assert "kms_key_id" not in (tmp_path / "main.tf").read_text()


def test_a_declaration_in_another_module_does_not_count(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(LOG_GROUP)
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "kms.tf").write_text(KEY)
    _apply(tmp_path)
    assert "kms_key_id" not in (tmp_path / "main.tf").read_text()


def test_a_fix_replacing_a_value_is_held_to_the_same_rule(tmp_path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_x" "y" {\n  key = "old"\n}\n')
    from _apply_fixes import handle_apply_fixes

    entry = {
        "id": "X-Y-001",
        "fix_hcl": "key = aws_kms_key.k.arn",
        "patterns": [{"kind": "resource_arg", "resource": "aws_x", "arg": "key"}],
    }
    finding = {
        "id": "X-Y-001",
        "file": str(tmp_path / "main.tf"),
        "line": 1,
        "resource": "aws_x.y",
    }
    handle_apply_fixes(None, [finding], [entry], dry_run=False)
    assert 'key = "old"' in (tmp_path / "main.tf").read_text()


def test_placeholder_values_are_not_pasted(tmp_path) -> None:
    from _apply_fixes import handle_apply_fixes

    (tmp_path / "main.tf").write_text('resource "aws_x" "y" {\n  name = "n"\n}\n')
    entry = {
        "id": "X-Y-001",
        "fix_hcl": 'key_name = "projects/example/keyRings/r/cryptoKeys/k"',
        "patterns": [
            {"kind": "resource_missing_arg", "resource": "aws_x", "arg": "key_name"}
        ],
    }
    finding = {
        "id": "X-Y-001",
        "file": str(tmp_path / "main.tf"),
        "line": 1,
        "resource": "aws_x.y",
    }
    handle_apply_fixes(None, [finding], [entry], dry_run=False)
    assert "key_name" not in (tmp_path / "main.tf").read_text()


def test_the_count_is_of_files_really_changed(tmp_path, capsys) -> None:
    from _apply_fixes import handle_apply_fixes

    (tmp_path / "main.tf").write_text(SQS)
    entry = {
        "id": "X-Y-001",
        "fix_hcl": "kms_master_key_id = aws_kms_key.sqs.arn",
        "patterns": [
            {
                "kind": "resource_missing_arg",
                "resource": "aws_sqs_queue",
                "arg": "kms_master_key_id",
            }
        ],
    }
    finding = {
        "id": "X-Y-001",
        "file": str(tmp_path / "main.tf"),
        "line": 1,
        "resource": "aws_sqs_queue.q",
    }
    handle_apply_fixes(None, [finding], [entry], dry_run=False)
    assert "applied 0 fix(es) across 0 file(s)" in capsys.readouterr().err


@pytest.mark.parametrize(
    "snippet, declared, missing",
    [
        ("a = aws_kms_key.k.arn", {"aws_kms_key.k"}, []),
        ("a = aws_kms_key.k.arn", set(), ["aws_kms_key.k"]),
        ('a = "${aws_kms_key.k.arn}/x"', set(), ["aws_kms_key.k"]),
        ('a = "$${aws_kms_key.k.arn}"', set(), []),
        ('a = "aws_kms_key.k.arn"', set(), []),
        ("a = var.x", set(), ["var.x"]),
        ("a = var.x", {"var.x"}, []),
        ("a = local.x", {"local.x"}, []),
        ("a = module.m.out", set(), ["module.m"]),
        ("a = data.aws_ami.u.id", set(), ["data.aws_ami.u"]),
        ("a = each.key", set(), []),
        ("a = count.index", set(), []),
        ("a = path.module", set(), []),
        ("a = self.id", set(), []),
        ("a = aws_x.y[0].id", set(), ["aws_x.y"]),
        ('resource "aws_kms_key" "k" {}\nb = aws_kms_key.k.arn', set(), []),
        ("# a = var.x\nb = 1", set(), []),
    ],
)
def test_undeclared_references(snippet, declared, missing) -> None:
    assert undeclared_references(snippet, declared) == missing


def test_declared_names() -> None:
    text = (
        'resource "aws_kms_key" "k" {}\n'
        'data "aws_ami" "u" {}\n'
        'variable "v" {}\n'
        'module "m" {\n  source = "./m"\n}\n'
        "locals {\n  a = 1\n  b = {\n    nested = 2\n  }\n}\n"
        '# resource "aws_x" "commented" {}\n'
    )
    assert declared_names(text) == {
        "aws_kms_key.k",
        "data.aws_ami.u",
        "var.v",
        "module.m",
        "local.a",
        "local.b",
    }


@pytest.mark.parametrize(
    "value",
    [
        "projects/example/locations/us/keyRings/k",
        "203.0.113.0/24",
        "198.51.100.7",
        "CHANGE_ME",
        "replace-me",
        "your-bucket",
        "<project-id>",
        "TODO",
        "123456789012",
    ],
)
def test_placeholders_are_recognised(value) -> None:
    assert placeholder_values(f'a = "{value}"') == [value]


@pytest.mark.parametrize(
    "value",
    [
        "SSE_KMS",
        "aws:kms",
        "alias/aws/sqs",
        "2592000s",
        "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
        "TLS1_2",
        "10.0.0.0/8",
        "examples-of-nothing",
    ],
)
def test_real_values_are_not_placeholders(value) -> None:
    assert placeholder_values(f'a = "{value}"') == []


def test_a_block_label_is_not_a_value() -> None:
    assert placeholder_values('resource "aws_x" "example" {\n  a = 1\n}') == []


def _patch_snippets(entry: dict):
    fix = entry.get("fix_hcl_minimal") or entry.get("fix_hcl") or ""
    for pat in entry.get("patterns") or []:
        kind, arg = pat.get("kind"), pat.get("arg")
        if not arg or kind not in ("resource_missing_arg", "resource_arg", "hcl_attr"):
            continue
        raw = fix_line_for_arg(fix, arg)
        if not raw and kind == "resource_missing_arg":
            raw = fix_block_for_nested_arg(fix, arg)
        if raw:
            yield raw


def test_the_bot_tier_holds_nothing_that_needs_a_person() -> None:
    """`fix_disruption: none` is what the bot applies unattended. A fix that
    needs another resource or a real value is not that."""
    wrong = {}
    for entry in _catalog():
        if entry.get("fix_disruption") != "none" or entry.get("fix_hcl_example"):
            continue
        for snippet in _patch_snippets(entry):
            reason = fix_blocker(snippet, set())
            if reason:
                wrong[entry["id"]] = reason
    assert not wrong


_REFERENCE = re.compile(
    r"(?<![\w.\-\"/:])(?:var\.[\w-]+|local\.[\w-]+|module\.[\w-]+|data\.[\w-]+\.[\w-]+"
    r"|[a-z][a-z0-9]*_[\w-]*\.[A-Za-z_][\w-]*)"
)


@pytest.mark.parametrize(
    "flags",
    [(), ("--apply-fixes-max-disruption", "none")],
    ids=["all-tiers", "bot-path"],
)
def test_no_fixture_gains_an_undeclared_reference(tmp_path, flags) -> None:
    """The whole catalogue on the whole fixture set: every added line, read
    with a separate regex and a separate list of what each folder declares."""
    copy = tmp_path / "fixtures"
    shutil.copytree(REPO / "fixtures", copy)
    before = {p: p.read_text(errors="replace") for p in copy.rglob("*.tf")}
    res = _apply(copy, "--no-suppress", *flags)
    assert res.returncode == 0, res.stderr[-500:]
    assert re.search(r"applied [1-9]\d* fix", res.stderr)

    bad = []
    for path, old in before.items():
        new = path.read_text(errors="replace")
        if new == old:
            continue
        added = [ln for ln in new.splitlines() if ln not in set(old.splitlines())]
        siblings = "\n".join(
            p.read_text(errors="replace") for p in path.parent.glob("*.tf")
        )
        known = {
            f"{m[0]}.{m[1]}"
            for m in re.findall(r'resource\s+"([\w-]+)"\s+"([\w-]+)"', siblings)
        }
        known |= {
            f"data.{m[0]}.{m[1]}"
            for m in re.findall(r'data\s+"([\w-]+)"\s+"([\w-]+)"', siblings)
        }
        known |= {f"var.{m}" for m in re.findall(r'variable\s+"([\w-]+)"', siblings)}
        for line in added:
            for ref in _REFERENCE.findall(re.sub(r'"[^"$]*"', '""', line)):
                if ref not in known:
                    bad.append(f"{path.name}: {line.strip()}")
            if re.search(r"\bexample\b|203\.0\.113\.", line):
                bad.append(f"{path.name}: {line.strip()}")
    assert not bad, bad[:10]


# ---- Paths that offer a fix as one click --------------------------------------


def test_findings_say_when_a_fix_can_not_be_taken_as_it_stands(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(LOG_GROUP)
    out = subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(tmp_path),
            "--format",
            "json",
            "--no-threat-intel",
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    cwl = [f for f in json.loads(out)["findings"] if f["id"] == "SEC-AWS-CWL-001"]
    assert cwl and "aws_kms_key.logs" in cwl[0]["fix_manual_reason"]


def test_annotation_uses_the_files_own_module(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(LOG_GROUP)
    (tmp_path / "kms.tf").write_text(KEY)
    entry = {"id": "X-Y-001", "fix_hcl": "kms_key_id = aws_kms_key.logs.arn"}
    finding = {"id": "X-Y-001", "file": str(tmp_path / "main.tf")}
    annotate_fix_blockers([finding], [entry])
    assert "fix_manual_reason" not in finding


def test_example_fixes_are_annotated_too(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(SQS)
    entry = {"id": "X-Y-001", "fix_hcl": "a = 1", "fix_hcl_example": True}
    finding = {"id": "X-Y-001", "file": str(tmp_path / "main.tf")}
    annotate_fix_blockers([finding], [entry])
    assert "examples" in finding["fix_manual_reason"]


@pytest.mark.parametrize("path", ["action.yml", "integrations/github-action.yml"])
def test_the_github_actions_post_no_suggestion_for_such_a_fix(path) -> None:
    text = (REPO / path).read_text()
    assert "!f.fix_suggestion" in text


def test_the_pr_body_counts_a_real_run_and_lists_what_is_left() -> None:
    from render_pr_body import compose_body

    scan = {
        "summary": {},
        "findings": [
            {
                "id": "SEC-AWS-CWL-001",
                "file": "main.tf",
                "line": 1,
                "fix_disruption": "none",
            },
            {
                "id": "OPS-AWS-CWL-001",
                "file": "main.tf",
                "line": 1,
                "fix_disruption": "none",
            },
        ],
    }
    body = compose_body(
        scan,
        (
            "# apply-fixes: applied 1 fix(es) across 1 file(s)\n"
            "# apply-fixes: 1 fix(es) left for you to do by hand:\n"
            "# apply-fixes: manual: SEC-AWS-CWL-001 main.tf:1 aws_x.y: references aws_kms_key.k\n"
        ),
    )
    assert "**1 non-disruptive fix(es)** across 1 file(s)" in body
    assert "### Needs manual work" in body and "SEC-AWS-CWL-001" in body
    assert "`SEC-AWS-CWL-*`" not in body and "`OPS-AWS-CWL-*`" in body


def test_pr_review_posts_advice_not_a_suggestion(tmp_path, monkeypatch) -> None:
    from argparse import Namespace

    captured: list[dict] = []

    class Resp:
        status = 200

        def __init__(self, body):
            self.body = body

        def read(self):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, *a, **k):
        if req.data:
            captured.append(json.loads(req.data))
            return Resp(b"{}")
        if "/files" not in req.full_url:
            return Resp(b'{"head": {"sha": "abc"}}')
        return Resp(
            json.dumps(
                [
                    {
                        "filename": "main.tf",
                        "patch": "@@ -0,0 +1,2 @@\n+a\n+b\n",
                    }
                ]
            ).encode()
        )

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    entry = {
        "id": "X-Y-001",
        "title": "t",
        "default_urgency": "HIGH",
        "fix_hcl": "kms_key_id = aws_kms_key.logs.arn",
    }
    finding = {
        "id": "X-Y-001",
        "file": "main.tf",
        "line": 1,
        "resource": "aws_x.y",
        "urgency": "HIGH",
        "fix_manual_reason": "references aws_kms_key.logs",
    }
    args = Namespace(repo="o/r", pr_number=1, targets=[], github_api_url=None)
    try:
        detect._pr_review_mode(args, [finding], [entry])
    except SystemExit:
        pass
    bodies = [c["body"] for post in captured for c in post.get("comments", [])]
    assert bodies, captured
    assert "```suggestion" not in bodies[0]
    assert "Fix needs manual work" in bodies[0]
