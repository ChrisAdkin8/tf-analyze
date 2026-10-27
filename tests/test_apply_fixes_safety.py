"""`--apply-fixes` must never leave a file worse than it found it
(critical review, 2026-10-27).

- A value that spans several lines is replaced whole; only its first
  line used to be, leaving the rest behind as invalid HCL.
- A multi-line fix is re-indented to the file's own indentation and line
  endings; it kept the catalogue snippet's.
- Files are read and written as UTF-8 (not the locale's encoding), and a
  file that is not UTF-8 is skipped rather than rewritten.
- The write is atomic and keeps the file's permissions.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from _apply_fixes import _value_end_line, code_lines
from _hcl import _parse_tf_cached

REPO = Path(__file__).resolve().parents[1]
RULE = "STK-AWS-EKS-005"  # enabled_cluster_log_types missing audit / authenticator

EKS = """\
resource "aws_eks_cluster" "c" {
%(i)sname     = "c"
%(i)srole_arn = "arn:aws:iam::123456789012:role/eks"
%(i)senabled_cluster_log_types = [
%(i)s%(i)s"api",   # café
%(i)s]
%(i)svpc_config {
%(i)s%(i)ssubnet_ids = ["subnet-1"]
%(i)s}
}
"""


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


def _ids(target: Path) -> set[str]:
    return {f["id"] for f in json.loads(_detect(target).stdout)["findings"]}


def _write(tmp_path: Path, text: str, newline: str = "\n") -> Path:
    tf = tmp_path / "main.tf"
    tf.write_bytes(text.replace("\n", newline).encode("utf-8"))
    return tf


def _apply(tmp_path: Path) -> subprocess.CompletedProcess:
    proc = _detect(tmp_path, "--apply-fixes", "apply")
    assert proc.returncode in (0, 1), proc.stderr
    return proc


def _valid_hcl(text: str) -> bool:
    # The engine normalises line endings before parsing; so does this.
    return _parse_tf_cached(text.replace("\r\n", "\n"))[1] is None


@pytest.mark.parametrize("indent", ["  ", "    ", "\t"])
def test_multi_line_value_is_replaced_whole_and_reindented(
    tmp_path: Path, indent: str
) -> None:
    tf = _write(tmp_path, EKS % {"i": indent})
    assert RULE in _ids(tmp_path)
    _apply(tmp_path)
    text = tf.read_text(encoding="utf-8")
    assert _valid_hcl(text), text
    assert '"api",   # café' not in text, "the old list's lines were left behind"
    assert text.count("enabled_cluster_log_types") == 1
    # The new list sits at the file's own indentation, not the snippet's.
    lines = text.splitlines()
    i = next(n for n, line in enumerate(lines) if "enabled_cluster_log_types" in line)
    assert lines[i].startswith(indent + "enabled") and not lines[i].startswith(
        indent * 2
    )
    assert lines[i + 1].startswith(indent * 2 + '"api"')
    assert lines[i + 2] == indent + "]"
    assert RULE not in _ids(tmp_path)


def test_multi_line_fix_keeps_crlf(tmp_path: Path) -> None:
    tf = _write(tmp_path, EKS % {"i": "  "}, newline="\r\n")
    _apply(tmp_path)
    raw = tf.read_bytes()
    assert b"\n" not in raw.replace(b"\r\n", b""), "a bare LF line was inserted"
    assert _valid_hcl(raw.decode("utf-8"))


def test_non_ascii_text_round_trips(tmp_path: Path) -> None:
    tf = _write(tmp_path, "# Équipe: données\n" + EKS % {"i": "  "})
    _apply(tmp_path)
    text = tf.read_text(encoding="utf-8")
    assert text.startswith("# Équipe: données\n")


def test_a_file_that_is_not_utf8_is_skipped(tmp_path: Path) -> None:
    tf = tmp_path / "main.tf"
    original = ("# caf\xe9\n" + EKS % {"i": "  "}).encode("latin-1")
    tf.write_bytes(original)
    proc = _apply(tmp_path)
    assert tf.read_bytes() == original
    # The scan already refuses the file; apply-fixes also re-checks it.
    assert "not UTF-8" in proc.stderr or "cannot read" in proc.stderr
    assert not list(tmp_path.glob("main.tf.bak*"))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_write_is_atomic_and_keeps_permissions(tmp_path: Path) -> None:
    tf = _write(tmp_path, EKS % {"i": "  "})
    tf.chmod(0o640)
    _apply(tmp_path)
    assert (tf.stat().st_mode & 0o777) == 0o640
    assert not list(tmp_path.glob(".main.tf.*.tmp")), "temporary file left behind"
    assert list(tmp_path.glob("main.tf.bak")), "backup not written"


# ---- where a value ends ---------------------------------------------------------


def _end(text: str, li: int = 0) -> int:
    lines = text.splitlines(keepends=True)
    return _value_end_line(lines, code_lines(lines), li)


def test_value_end_single_line() -> None:
    assert _end('a = ["x", "y"]\nb = 1\n') == 0


def test_value_end_multi_line_list_and_call() -> None:
    assert _end('a = [\n  "x",\n]\nb = 1\n') == 2
    assert _end('a = jsonencode({\n  k = "v"\n})\nb = 1\n') == 2


def test_value_end_ignores_brackets_in_strings_and_comments() -> None:
    assert _end('a = "x[" # {\nb = 1\n') == 0


def test_value_end_heredoc() -> None:
    assert _end("a = <<-EOF\n  [ not a bracket\n  EOF\nb = 1\n") == 2
