"""A one-click suggestion overwrites one line, so it must fit that line.

Suggestions pasted the whole `fix_hcl`, and `resource "x" "example" {` went
over the user's own resource header.
"""

from __future__ import annotations

import json
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
from _apply_fixes import annotate_fix_blockers
from _hcl import parse_tf


def _report(target: Path, *flags: str) -> list[dict]:
    out = subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(target),
            "--format",
            "json",
            "--no-threat-intel",
            "--no-suppress",
            *flags,
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    return json.loads(out)["findings"]


def _accept(path: Path, line: int, text: str) -> str:
    lines = path.read_text().split("\n")
    lines[line - 1 : line] = text.split("\n")
    return "\n".join(lines)


def test_a_missing_argument_keeps_the_real_header(tmp_path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_db_instance" "mine" {\n  engine = "mysql"\n}\n')
    entry = {"id": "X-Y-001",
             "fix_hcl": 'resource "aws_db_instance" "example" {\n  name = "example"\n  deletion_protection = true\n}\n',
             "patterns": [{"kind": "resource_missing_arg", "resource": "aws_db_instance",
                           "arg": "deletion_protection"}]}
    finding = {"id": "X-Y-001", "file": str(tmp_path / "main.tf"), "line": 1,
               "resource": "aws_db_instance.mine"}
    annotate_fix_blockers([finding], [entry], suggestions=True)
    assert finding["fix_suggestion"] == (
        'resource "aws_db_instance" "mine" {\n  deletion_protection = true'
    )


def test_a_change_on_another_line_is_advice(tmp_path) -> None:
    """A suggestion can only overwrite the line the finding is on."""
    (tmp_path / "main.tf").write_text('resource "aws_x" "y" {\n  public = true\n}\n')
    entry = {"id": "X-Y-001", "fix_hcl": "public = false",
             "patterns": [{"kind": "resource_arg", "resource": "aws_x", "arg": "public"}]}
    finding = {"id": "X-Y-001", "file": str(tmp_path / "main.tf"), "line": 1, "resource": "aws_x.y"}
    annotate_fix_blockers([finding], [entry], suggestions=True)
    assert "fix_suggestion" not in finding


@pytest.mark.parametrize(
    "entry",
    [
        {
            "id": "X-Y-001",
            "fix_hcl": "kms = aws_kms_key.k.arn",
            "patterns": [
                {"kind": "resource_missing_arg", "resource": "aws_x", "arg": "kms"}
            ],
        },
        {
            "id": "X-Y-001",
            "fix_hcl": "a = 1",
            "fix_hcl_example": True,
            "patterns": [
                {"kind": "resource_missing_arg", "resource": "aws_x", "arg": "a"}
            ],
        },
        {
            "id": "X-Y-001",
            "fix_hcl": 'resource "aws_x" "example" {\n  a = 1\n}\n',
            "patterns": [{"kind": "grep", "regex": "a"}],
        },
    ],
    ids=["refused", "example", "no-patch"],
)
def test_no_suggestion_without_a_patch_the_patcher_would_make(tmp_path, entry) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_x" "y" {\n  name = "n"\n}\n')
    finding = {
        "id": "X-Y-001",
        "file": str(tmp_path / "main.tf"),
        "line": 1,
        "resource": "aws_x.y",
    }
    annotate_fix_blockers([finding], [entry], suggestions=True)
    assert "fix_suggestion" not in finding


def test_an_inline_block_becomes_a_valid_block(tmp_path) -> None:
    path = tmp_path / "main.tf"
    path.write_text('resource "aws_x" "y" { name = "n" }\n')
    entry = {"id": "X-Y-001", "fix_hcl": "a = 1",
             "patterns": [{"kind": "resource_missing_arg", "resource": "aws_x", "arg": "a"}]}
    finding = {"id": "X-Y-001", "file": str(path), "line": 1, "resource": "aws_x.y"}
    annotate_fix_blockers([finding], [entry], suggestions=True)
    assert parse_tf(_accept(path, 1, finding["fix_suggestion"]))[1] is None


def test_an_unsaved_buffer_is_what_counts(tmp_path) -> None:
    path = tmp_path / "main.tf"
    path.write_text("# nothing yet\n")
    entry = {
        "id": "X-Y-001",
        "fix_hcl": "a = 1",
        "patterns": [{"kind": "resource_missing_arg", "resource": "aws_x", "arg": "a"}],
    }
    finding = {"id": "X-Y-001", "file": str(path), "line": 1, "resource": "aws_x.y"}
    annotate_fix_blockers(
        [finding], [entry], {str(path): 'resource "aws_x" "y" {\n}\n'}, suggestions=True,
    )
    assert finding["fix_suggestion"] == 'resource "aws_x" "y" {\n  a = 1'


@pytest.mark.parametrize("cloud", ["aws", "gcp", "azure"])
def test_terragoat_suggestions_all_apply_cleanly(tmp_path, cloud) -> None:
    copy = tmp_path / cloud
    shutil.copytree(REPO / "examples" / "terragoat" / cloud, copy)
    suggested = [f for f in _report(copy, "--fix-suggestions") if f.get("fix_suggestion")]
    assert suggested
    for f in suggested:
        path = Path(f["file"])
        before = path.read_text().split("\n")[f["line"] - 1]
        text = f["fix_suggestion"]
        assert '"example"' not in text, f["id"]
        if text.startswith(("resource ", "data ")):
            assert text.split("\n")[0] == before, f["id"]  # the user's own header
        assert parse_tf(_accept(path, f["line"], text))[1] is None, (f["id"], text)


def test_every_fixture_suggestion_is_header_or_value(tmp_path) -> None:
    copy = tmp_path / "fixtures"
    shutil.copytree(REPO / "fixtures", copy)
    for f in _report(copy, "--fix-suggestions"):
        text = f.get("fix_suggestion")
        if text:
            assert "fix_manual_reason" not in f
            first = text.split("\n")[0]
            assert first == Path(f["file"]).read_text().split("\n")[
                f["line"] - 1
            ] or not first.startswith("resource ")


def test_pr_review_pastes_the_suggestion_only(monkeypatch) -> None:
    from argparse import Namespace

    captured: list[dict] = []

    class Resp:
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
            return Resp(b'{"html_url": "u"}')
        if "/files" not in req.full_url:
            return Resp(b'{"head": {"sha": "abc"}}')
        return Resp(
            json.dumps(
                [{"filename": "main.tf", "patch": "@@ -0,0 +1,2 @@\n+a\n+b\n"}]
            ).encode()
        )

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    entries = [
        {
            "id": f"X-Y-00{i}",
            "title": "t",
            "default_urgency": "HIGH",
            "fix_hcl": 'resource "aws_x" "example" {\n  a = 1\n}',
        }
        for i in (1, 2)
    ]
    findings = [
        {
            "id": "X-Y-001",
            "file": "main.tf",
            "line": 1,
            "resource": "aws_x.y",
            "urgency": "HIGH",
            "fix_suggestion": 'resource "aws_x" "y" {\n  a = 1',
        },
        {
            "id": "X-Y-002",
            "file": "main.tf",
            "line": 2,
            "resource": "aws_x.y",
            "urgency": "HIGH",
        },
    ]
    detect._pr_review_mode(
        Namespace(repo="o/r", pr_number=1, targets=[]), findings, entries
    )
    first, second = [c["body"] for c in captured[0]["comments"]]
    assert '```suggestion\nresource "aws_x" "y" {\n  a = 1\n```' in first
    assert "example" not in first.split("```suggestion")[1]
    assert "```suggestion" not in second and "```hcl" in second


def test_the_quick_fix_replaces_the_line_with_the_suggestion(tmp_path) -> None:
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
        rid = lsp.send_request(
            "textDocument/codeAction",
            {
                "textDocument": {"uri": uri},
                "range": {
                    "start": {"line": 0, "character": 0},
                    "end": {"line": 0, "character": 0},
                },
                "context": {"diagnostics": msg["params"]["diagnostics"]},
            },
        )
        actions = lsp.read_response(rid, timeout=10.0)["result"]
    assert actions
    for action in actions:
        edit = action["edit"]["changes"][uri][0]
        assert edit["range"] == {
            "start": {"line": 0, "character": 0},
            "end": {"line": 1, "character": 0},
        }
        assert edit["newText"].startswith(
            'resource "aws_cloudwatch_log_group" "lg" {\n'
        )
        assert "example" not in edit["newText"]


def test_a_plain_scan_computes_no_suggestions(tmp_path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_cloudwatch_log_group" "lg" {\n  name = "x"\n}\n')
    assert not [f for f in _report(tmp_path) if "fix_suggestion" in f]
    assert [f for f in _report(tmp_path, "--fix-suggestions") if "fix_suggestion" in f]


@pytest.mark.parametrize("char", ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"])
def test_only_line_endings_end_a_line(tmp_path, char) -> None:
    """`str.splitlines` breaks on these too, and the fix then missed its line."""
    path = tmp_path / "main.tf"
    text = f'locals {{\n  a = "x{char}y"\n}}\n\nresource "aws_x" "y" {{\n  name = "n"\n}}\n'
    entry = {"id": "X-Y-001", "fix_hcl": "a = 1",
             "patterns": [{"kind": "resource_missing_arg", "resource": "aws_x", "arg": "a"}]}
    finding = {"id": "X-Y-001", "file": str(path), "line": 5, "resource": "aws_x.y"}
    path.write_text("")
    annotate_fix_blockers([finding], [entry], {str(path): text}, suggestions=True)
    assert finding["fix_suggestion"] == 'resource "aws_x" "y" {\n  a = 1'
