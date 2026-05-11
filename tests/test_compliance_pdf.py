"""Tests for `--pdf-output` (R30.13 — Compliance PDF export).

weasyprint is an optional dep. Tests check both branches:
  * Installed → PDF file is written, starts with the magic header.
  * Missing → engine exits 2 with a clean install hint.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from helpers import DETECT_PY, FIXTURES_DIR


try:
    import weasyprint  # noqa: F401
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False


@pytest.mark.skipif(not HAS_WEASYPRINT, reason="weasyprint not installed")
def test_pdf_output_writes_pdf(tmp_path: Path) -> None:
    out = tmp_path / "compliance.pdf"
    proc = subprocess.run(
        [sys.executable, str(DETECT_PY),
         "--target", str(FIXTURES_DIR / "aws_iam_policy_wildcard_action"),
         "--compliance", "--compliance-framework", "nist_csf",
         "--pdf-output", str(out)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert out.exists()
    # PDF magic header.
    assert out.read_bytes()[:5] == b"%PDF-"
    assert "PDF compliance report written to" in proc.stderr


@pytest.mark.skipif(HAS_WEASYPRINT, reason="weasyprint installed; can't test the missing-dep path")
def test_pdf_output_clean_error_when_weasyprint_missing(tmp_path: Path) -> None:
    out = tmp_path / "compliance.pdf"
    proc = subprocess.run(
        [sys.executable, str(DETECT_PY),
         "--target", str(FIXTURES_DIR / "aws_iam_policy_wildcard_action"),
         "--compliance", "--pdf-output", str(out)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 2
    assert "weasyprint" in proc.stderr
    assert "pip install weasyprint" in proc.stderr
    assert not out.exists()
