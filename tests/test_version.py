"""The version has one source, scripts/_meta.py; every surface reads it."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from _meta import __version__

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "fixtures" / "aws_sg_open"


def _detect(*args: str) -> str:
    return subprocess.run(
        [sys.executable, str(REPO / "scripts" / "detect.py"), *args],
        capture_output=True,
        text=True,
        check=False,
    ).stdout


def test_version_is_a_release_number() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:[-.][\w.]+)?", __version__)


def test_version_flag() -> None:
    assert _detect("--version").strip() == f"tf-analyze {__version__}"


def test_sarif_and_json_report_the_version() -> None:
    sarif = json.loads(_detect("--target", str(FIXTURE), "--format", "sarif"))
    assert sarif["runs"][0]["tool"]["driver"]["version"] == __version__
    report = json.loads(_detect("--target", str(FIXTURE), "--format", "json"))
    assert report["tool_version"] == __version__


def test_package_metadata_reads_the_same_source() -> None:
    pyproject = (REPO / "pyproject.toml").read_text()
    assert 'dynamic = ["version"]' in pyproject
    assert 'version = { attr = "_meta.__version__" }' in pyproject
    assert not re.search(r'(?m)^version\s*=\s*"', pyproject)  # no second copy


def test_no_hard_coded_engine_versions_left() -> None:
    for name in ("_output.py", "_lsp.py"):
        text = (REPO / "scripts" / name).read_text()
        assert '"version": "1.2.0"' not in text
        assert '"version": "0.1.0"' not in text
