"""`--apply-fixes` on ordinary files: braces in comments and strings,
CRLF files, repeated runs, the dry-run diff, suppressed findings, and a
finding whose argument is present but wrong (critical review)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from _apply_fixes import code_lines, find_block_end_in_lines
from _hcl import _parse_tf_cached


def parse_tf(text: str):
    """The real parser, also under TF_ANALYZE_TEST_FORCE_FALLBACK (whose
    `_hcl.parse_tf` returns no tree): these checks are about the file
    being valid HCL, whichever path the engine scanned it with."""
    return _parse_tf_cached(text)

REPO = Path(__file__).resolve().parents[1]
RULE = "SEC-AWS-RDS-002"  # aws_db_instance storage_encrypted (missing or false)


def _detect(target: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(target),
            "--format",
            "json",
            *args,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _fires(target: Path) -> bool:
    findings = json.loads(_detect(target).stdout)["findings"]
    return any(f["id"] == RULE for f in findings)


def _write(tmp_path: Path, text: str, *, newline: str = "\n") -> Path:
    tf = tmp_path / "main.tf"
    tf.write_bytes(text.replace("\n", newline).encode())
    return tf


def _apply(tmp_path: Path) -> None:
    proc = _detect(tmp_path, "--apply-fixes", "apply")
    assert proc.returncode in (0, 1), proc.stderr


@pytest.mark.parametrize(
    "tag_line",
    [
        'Name = "db" # see the closing } below',  # brace in a comment
        'Note = "a } literal"',  # brace in a string
    ],
)
def test_braces_in_comments_and_strings_do_not_misplace_the_fix(tmp_path, tag_line) -> None:
    tf = _write(tmp_path, (
        'resource "aws_db_instance" "db" {\n'
        '  engine = "postgres"\n'
        "  tags = {\n"
        f"    {tag_line}\n"
        "  }\n"
        "}\n"
    ))
    _apply(tmp_path)
    text = tf.read_text()
    tree, error = parse_tf(text)
    assert error is None, text
    attrs = tree["resource"][0]["aws_db_instance"]["db"]
    assert attrs.get("storage_encrypted") is True, text  # top level, not inside tags
    assert "storage_encrypted" not in attrs["tags"]
    assert not _fires(tmp_path)


def test_code_lines_blanks_comments_and_strings_only() -> None:
    lines = ['x = "{" # }\n', "y = {\n", "}\n"]
    assert [ln.count("{") - ln.count("}") for ln in code_lines(lines)] == [0, 1, -1]
    assert find_block_end_in_lines(lines, 1) == 2


def test_crlf_line_endings_are_kept(tmp_path) -> None:
    tf = _write(
        tmp_path,
        'resource "aws_db_instance" "db" {\n  engine = "postgres"\n}\n',
        newline="\r\n",
    )
    _apply(tmp_path)
    data = tf.read_bytes()
    assert b"storage_encrypted" in data
    assert data.count(b"\r\n") == data.count(b"\n"), data  # every line still CRLF


def test_a_second_run_keeps_the_original_backup(tmp_path) -> None:
    original = 'resource "aws_db_instance" "db" {\n  engine = "postgres"\n}\n'
    tf = _write(tmp_path, original)
    _apply(tmp_path)
    after_first = tf.read_text()
    tf.write_text(
        after_first.replace("storage_encrypted = true", "storage_encrypted = false")
    )
    _apply(tmp_path)
    assert (tmp_path / "main.tf.bak").read_text() == original
    assert (tmp_path / "main.tf.bak.1").exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_dry_run_prints_a_patch_git_can_apply(tmp_path) -> None:
    _write(tmp_path, 'resource "aws_db_instance" "db" {\n  engine = "postgres"\n}\n')
    diff = _detect(tmp_path, "--apply-fixes", "dry-run").stdout
    diff = (
        diff[diff.index("---") : diff.index("\n{") + 1]
        if "\n{" in diff
        else diff[diff.index("---") :]
    )
    assert "\n\n" not in diff  # lines used to come out doubled
    patch = tmp_path / "fix.patch"
    patch.write_text(
        diff.replace(f"{tmp_path}/main.tf.orig", "a/main.tf").replace(
            f"{tmp_path}/main.tf", "b/main.tf"
        )
    )
    check = subprocess.run(
        ["git", "apply", "--check", "-p1", str(patch)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert check.returncode == 0, check.stderr + diff


def test_suppressed_findings_are_not_patched(tmp_path) -> None:
    tf = _write(tmp_path, (
        f"# tf-analyze:ignore {RULE} cannot replace this database\n"
        'resource "aws_db_instance" "db" {\n'
        '  engine = "postgres"\n'
        "}\n"
    ))
    _apply(tmp_path)
    # Other, unsuppressed findings on the resource may be patched; the
    # suppressed rule's fix (a replacement-forcing change) must not be.
    assert "storage_encrypted" not in tf.read_text()


def test_argument_set_to_false_is_corrected(tmp_path) -> None:
    tf = _write(
        tmp_path,
        (
            'resource "aws_db_instance" "db" {\n'
            '  engine            = "postgres"\n'
            "  storage_encrypted = false\n"
            "}\n"
        ),
    )
    assert _fires(tmp_path)
    _apply(tmp_path)
    assert "storage_encrypted = true" in tf.read_text()
    assert not _fires(tmp_path)


def test_fix_values_spanning_lines_are_taken_whole() -> None:
    from _apply_fixes import fix_line_for_arg

    assert fix_line_for_arg('a = [\n  "x",\n  "y",\n]\n', "a") == 'a = [\n  "x",\n  "y",\n]'
    assert fix_line_for_arg("a = jsonencode({\n  k = 1\n})\n", "a") == "a = jsonencode({\n  k = 1\n})"
    assert fix_line_for_arg('a = "s[t"\n', "a") == 'a = "s[t"'  # bracket inside a string


def test_applying_every_fix_to_terragoat_leaves_valid_hcl(tmp_path) -> None:
    corpus = tmp_path / "terragoat"
    shutil.copytree(REPO / "examples" / "terragoat", corpus)
    proc = _detect(corpus, "--apply-fixes", "apply")
    assert "apply-fixes: applied" in proc.stderr, proc.stderr
    broken = [
        f.relative_to(corpus).as_posix()
        for f in corpus.rglob("*.tf")
        if parse_tf(f.read_text())[1]
    ]
    assert broken == []
