"""Parser migration Step 2 (tasks/hcl-parser-migration.md §4.3–4.8, §8).

Pins: resources get their parsed subtree (`attrs`) joined from python-hcl2;
presence checks are top-level and every-instance on both the tree path and
the regex fallback (and the two agree on every fixture); `instances: any`
opts out; files the parser rejects are still scanned and are reported as a
tool diagnostic — in every output format, through the cache, and in the LSP
— without affecting the score.
"""
from __future__ import annotations

import collections
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS = REPO_ROOT / "scripts"
DETECT_PY = SCRIPTS / "detect.py"
sys.path.insert(0, str(SCRIPTS))

import _hcl  # noqa: E402
import detect  # noqa: E402


def _entry(path: str, resource: str = "aws_thing", **extra) -> dict:
    pat = {"kind": "resource_missing_arg", "resource": resource, **extra}
    pat["nested_path" if "." in path else "arg"] = path
    return {"id": "TEST-STEP2-001", "default_urgency": "LOW", "patterns": [pat]}


def _fires(text: str, entry: dict, tmp_path: Path) -> bool:
    fp = tmp_path / "main.tf"
    fp.write_text(text)
    return bool(detect.detect_in_file(fp, text, [entry]))


@pytest.fixture(autouse=True)
def _real_parser(monkeypatch):
    """These tests are about the parse tree itself, so they always run with
    the real parser — even inside the CI job that forces the regex
    fallback for the rest of the suite. `path_mode` re-enables the
    fallback where a test covers both paths."""
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)


@pytest.fixture(params=["tree", "fallback"])
def path_mode(request, monkeypatch):
    """Run a test on the parse-tree path and again on the regex fallback."""
    if request.param == "fallback":
        monkeypatch.setenv("TF_ANALYZE_TEST_FORCE_FALLBACK", "1")
    else:
        monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)
    return request.param


# ---- joining the tree to regex blocks ---------------------------------------

def test_resources_get_attrs_from_the_tree(tmp_path) -> None:
    text = 'resource "aws_thing" "a" {\n  name = "x"\n}\n'
    resources = detect.find_blocks(text, detect.RESOURCE_START)
    tree, err = _hcl.parse_tf(text)
    assert err is None
    assert _hcl.resource_subtrees(tree)[("aws_thing", "a")][0]["name"] == "x"
    # detect_in_file attaches it; observable through a presence check.
    assert not _fires(text, _entry("name"), tmp_path)
    assert resources[0]["start_line"] == 1


def test_heredoc_resource_text_is_not_a_block(tmp_path) -> None:
    # `resource` text inside a heredoc is not a block: the scanner and the
    # tree agree on one aws_thing.a, so the tree path is used.
    text = (
        'resource "aws_thing" "a" {\n'
        '  doc = <<EOT\n'
        'resource "aws_thing" "a" {\n'
        '}\n'
        'EOT\n'
        '}\n'
    )
    tree, _ = _hcl.parse_tf(text)
    assert len(_hcl.resource_subtrees(tree)[("aws_thing", "a")]) == 1
    blocks = detect.find_blocks(text, detect.RESOURCE_START)
    assert len(blocks) == 1 and blocks[0]["block_text"] == text.rstrip("\n")
    assert _fires(text, _entry("name"), tmp_path)


def test_ambiguous_resource_key_falls_back(tmp_path) -> None:
    # Two blocks with one address (invalid Terraform): the key is
    # ambiguous, so both are scanned through the regex fallback.
    text = (
        'resource "aws_thing" "a" {\n}\n'
        'resource "aws_thing" "a" {\n}\n'
    )
    assert len(detect.find_blocks(text, detect.RESOURCE_START)) == 2
    assert _fires(text, _entry("name"), tmp_path)  # still scanned


def test_bom_does_not_break_parsing() -> None:
    tree, err = _hcl.parse_tf('﻿resource "aws_thing" "a" {\n  name = "x"\n}\n')
    assert err is None and ("aws_thing", "a") in _hcl.resource_subtrees(tree)


# ---- presence semantics (§4.4), on both paths --------------------------------

def test_map_key_does_not_satisfy_top_level_arg(tmp_path, path_mode) -> None:
    text = (
        'resource "aws_thing" "a" {\n'
        '  tags = {\n'
        '    retention_in_days = "none"\n'
        '  }\n'
        '}\n'
    )
    assert _fires(text, _entry("retention_in_days"), tmp_path)


def test_nested_block_key_does_not_satisfy_top_level_arg(tmp_path, path_mode) -> None:
    text = (
        'resource "aws_thing" "a" {\n'
        '  logging {\n'
        '    retention_in_days = 3\n'
        '  }\n'
        '}\n'
    )
    assert _fires(text, _entry("retention_in_days"), tmp_path)
    assert not _fires(text, _entry("logging.retention_in_days"), tmp_path)


def test_nested_path_walks_a_named_map(tmp_path, path_mode) -> None:
    """docs/custom-rules.md's `tags.cost_center` example. Before the parser
    migration the regex helper only walked blocks (`tags {`), so this rule
    fired on every resource even with the tag set."""
    text = (
        'resource "aws_thing" "a" {\n'
        '  tags = {\n'
        '    cost_center = "platform-12345"\n'
        '  }\n'
        '}\n'
    )
    assert not _fires(text, _entry("tags.cost_center"), tmp_path)
    assert _fires(text, _entry("tags.owner"), tmp_path)


def test_heredoc_and_comment_text_are_not_settings(tmp_path, path_mode) -> None:
    text = (
        'resource "aws_thing" "a" {\n'
        '  # retention_in_days = 3\n'
        '  doc = <<EOT\n'
        'retention_in_days = 3\n'
        'EOT\n'
        '}\n'
    )
    assert _fires(text, _entry("retention_in_days"), tmp_path)


REPEATED = (
    'resource "aws_thing" "a" {\n'
    '  logging {\n'
    '    target = "a"\n'
    '  }\n'
    '  logging {\n'
    '    level = "info"\n'
    '  }\n'
    '}\n'
)


def test_repeated_block_requires_every_instance(tmp_path, path_mode) -> None:
    assert _fires(REPEATED, _entry("logging.target"), tmp_path)


def test_instances_any_opts_out(tmp_path, path_mode) -> None:
    assert not _fires(REPEATED, _entry("logging.target", instances="any"), tmp_path)


def test_dynamic_block_content_counts(tmp_path, path_mode) -> None:
    text = (
        'resource "aws_thing" "a" {\n'
        '  dynamic "logging" {\n'
        '    for_each = var.logs\n'
        '    content {\n'
        '      target = logging.value\n'
        '    }\n'
        '  }\n'
        '}\n'
    )
    assert not _fires(text, _entry("logging.target"), tmp_path)


def test_list_of_objects_attribute_form_on_tree_path(tmp_path) -> None:
    """`ingress = [{...}]` walks like `ingress {}` on the tree path. (The
    regex fallback does not handle this form; tasks/hcl-parser-migration.md
    §4.4 rule 2.)"""
    text = (
        'resource "aws_thing" "a" {\n'
        '  ingress = [\n'
        '    { description = "web" },\n'
        '    { description = "ssh" },\n'
        '  ]\n'
        '}\n'
    )
    assert not _fires(text, _entry("ingress.description"), tmp_path)
    assert _fires(text, _entry("ingress.cidr_blocks"), tmp_path)


def _missing_arg_paths() -> dict[str, set[tuple[str, bool]]]:
    paths: dict[str, set[tuple[str, bool]]] = collections.defaultdict(set)
    for e in detect.load_catalog(REPO_ROOT / "catalog"):
        for p in e.get("patterns") or []:
            if p.get("kind") == "resource_missing_arg" and p.get("resource"):
                path = p.get("nested_path") or p.get("arg")
                if path:
                    paths[p["resource"]].add((path, p.get("instances", "all") != "any"))
    return paths


def test_tree_and_regex_fallback_agree_on_every_fixture() -> None:
    """For every resource in fixtures/ and examples/, and every path a
    `resource_missing_arg` rule checks on that resource type, the tree and
    the regex fallback must give the same answer — so a file that fails to
    parse is judged by the same rules (tasks/hcl-parser-migration.md §4.7)."""
    paths = _missing_arg_paths()
    mismatches = []
    checked = 0
    for corpus in ("fixtures", "examples"):
        for tf in sorted((REPO_ROOT / corpus).rglob("*.tf")):
            text = _hcl._read_normalized(tf)
            tree, _ = _hcl.parse_tf(text)
            if tree is None:
                continue
            subtrees = _hcl.resource_subtrees(tree)
            for blk in _hcl.find_blocks(text, detect.RESOURCE_START):
                key = tuple(blk["groups"])
                found = subtrees.get(key, [])
                if len(found) != 1:
                    continue
                attrs = _hcl.normalise_attrs(found[0])
                body = _hcl._expand_dynamic_blocks(blk["body"])
                for path, every in paths.get(key[0], ()):
                    checked += 1
                    tree_ans = _hcl.attrs_has_path(attrs, path, every=every)
                    regex_ans = _hcl.resource_has_path(
                        {"body": body, "attrs": None}, path, every=every,
                    )
                    if tree_ans != regex_ans:
                        mismatches.append(
                            f"{tf.relative_to(REPO_ROOT)} {'.'.join(key)} {path}: "
                            f"tree={tree_ans} regex={regex_ans}"
                        )
    assert checked > 1000
    assert not mismatches, "\n".join(mismatches[:20])


# ---- top-level mask ---------------------------------------------------------

def test_mask_keeps_offsets_and_hides_non_top_level_text() -> None:
    body = '  x = "${lookup(m, "k")}" # c\n  y {\n    z = 1\n  }\n'
    masked = _hcl._mask_to_top_level(body)
    assert len(masked) == len(body)
    assert masked.count("\n") == body.count("\n")
    assert "lookup" not in masked and "# c" not in masked and "z" not in masked
    assert "x =" in masked and "y {" in masked


# ---- files the parser can't read (§4.8) -------------------------------------

UNPARSEABLE = (
    'resource "aws_security_group" "sg" {\n'
    '  name = "sg"\n'
    '  ingress { from_port = 22, to_port = 22 }\n'  # invalid HCL: commas
    '}\n'
    '\n'
    'resource "aws_cloudwatch_log_group" "l" {\n'
    '  name = "l"\n'
    '}\n'
)


def _run(target: Path, *argv: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(DETECT_PY), "--target", str(target), *argv],
        capture_output=True, text=True, timeout=120,
        env={**os.environ, **(env or {})},
    )


@pytest.fixture
def broken_dir(tmp_path) -> Path:
    (tmp_path / "main.tf").write_text(UNPARSEABLE)
    return tmp_path


def test_unparseable_file_is_still_scanned_and_reported(broken_dir) -> None:
    assert _hcl.parse_tf(UNPARSEABLE)[1]
    res = _run(broken_dir, "--format", "json")
    data = json.loads(res.stdout)
    ids = {f["id"] for f in data["findings"]}
    assert "COST-AWS-RISK-001" in ids  # found by the regex fallback
    pf = data["summary"]["parse_fallback_files"]
    assert [Path(p["file"]).name for p in pf] == ["main.tf"]
    assert pf[0]["reason"]
    assert "parse failed, scanned in fallback mode" in res.stderr


def test_parse_fallback_does_not_change_the_score(broken_dir) -> None:
    """Normal run (file fails to parse -> regex fallback + diagnostic) vs
    forced-fallback run (regex path, no diagnostic): same findings, so the
    diagnostic must not move the score or counts."""
    reported = json.loads(_run(broken_dir, "--format", "json").stdout)
    silent = json.loads(_run(broken_dir, "--format", "json",
                             env={"TF_ANALYZE_TEST_FORCE_FALLBACK": "1"}).stdout)
    assert "parse_fallback_files" in reported["summary"]
    assert "parse_fallback_files" not in silent["summary"]
    assert reported["findings"] == silent["findings"]
    assert reported["summary"]["score"] == silent["summary"]["score"]
    assert reported["summary"]["counts"] == silent["summary"]["counts"]


def test_parse_fallback_in_sarif_is_a_notification_not_a_result(broken_dir) -> None:
    sarif = json.loads(_run(broken_dir, "--format", "sarif").stdout)
    run = sarif["runs"][0]
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert run["invocations"][0]["executionSuccessful"] is True
    assert notes[0]["level"] == "warning"
    assert notes[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("main.tf")
    assert all(r["ruleId"] != "tf-analyze/parse-fallback" for r in run["results"])


@pytest.mark.parametrize("fmt", ["text", "pr-summary", "html"])
def test_parse_fallback_notice_in_human_formats(broken_dir, fmt) -> None:
    out = _run(broken_dir, "--format", fmt).stdout
    assert "scanned in fallback mode" in out


def test_no_notice_when_everything_parses(tmp_path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_cloudwatch_log_group" "l" {\n  name = "l"\n}\n')
    data = json.loads(_run(tmp_path, "--format", "json").stdout)
    assert "parse_fallback_files" not in data["summary"]
    sarif = json.loads(_run(tmp_path, "--format", "sarif").stdout)
    assert "invocations" not in sarif["runs"][0]


def test_parse_fallback_survives_a_cache_hit(broken_dir) -> None:
    first = json.loads(_run(broken_dir, "--format", "json", "--cache").stdout)
    second_res = _run(broken_dir, "--format", "json", "--cache")
    assert "cache hit" in second_res.stderr
    second = json.loads(second_res.stdout)
    assert second["summary"]["parse_fallback_files"] == first["summary"]["parse_fallback_files"]


def test_forced_fallback_reports_nothing(broken_dir) -> None:
    """The test-only switch disables the tree without reporting every file
    as a parse failure."""
    data = json.loads(_run(broken_dir, "--format", "json",
                           env={"TF_ANALYZE_TEST_FORCE_FALLBACK": "1"}).stdout)
    assert "parse_fallback_files" not in data["summary"]


def test_lsp_diagnostic_override() -> None:
    import _lsp
    diags = _lsp.findings_to_diagnostics(
        [{"id": "tf-analyze/parse-fallback", "line": 1,
          "lsp_severity": 3, "lsp_message": "scanned in fallback mode"}],
        {},
    )
    assert diags[0]["severity"] == 3
    assert diags[0]["message"] == "scanned in fallback mode"


def test_resource_index_is_built_once_per_corpus() -> None:
    import _cross_resource
    files = {"a.tf": 'resource "aws_thing" "a" {\n}\n'}
    first = _cross_resource._build_resource_index(files)
    assert _cross_resource._build_resource_index(dict(files)) is first
    other = _cross_resource._build_resource_index({"a.tf": 'resource "aws_thing" "b" {\n}\n'})
    assert other is not first and "aws_thing.b" in other
