"""Characterization harness for main()'s report-rendering tail.

Pins the externally-observable output contract of every `--format` across BOTH
render branches (the normal branch and the `--compare` delta branch) before the
~170-line render block is extracted out of `main()` into `_render_report`. Runs
the real `detect.py` as a subprocess against one fixed "dirty" fixture so the
extraction is provably behaviour-preserving.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
DETECT_PY = REPO_ROOT / "scripts" / "detect.py"

# Two textbook misconfigurations (public S3 ACL + SSH open to the world) so the
# scan reliably yields >=1 finding to render.
_DIRTY_TF = """\
resource "aws_s3_bucket" "b" {
  bucket = "x"
  acl    = "public-read"
}

resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


def _run(target: Path, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(DETECT_PY), "--no-hcl2", "--target", str(target), *argv],
        capture_output=True, text=True, timeout=120,
    )


@pytest.fixture
def dirty(tmp_path: Path) -> Path:
    d = tmp_path / "tf"
    d.mkdir()
    (d / "main.tf").write_text(_DIRTY_TF)
    return d


@pytest.fixture
def prior_json(dirty: Path, tmp_path: Path) -> Path:
    """A prior JSON report of the same fixture, for the --compare branch."""
    p = tmp_path / "prior.json"
    p.write_text(_run(dirty, "--format", "json").stdout)
    return p


# --------------------------------------------------------------------------- #
# Normal render branch — one assertion per format
# --------------------------------------------------------------------------- #
def test_json_structure(dirty: Path) -> None:
    r = _run(dirty, "--format", "json")
    assert r.returncode in (0, 1), r.stderr
    data = json.loads(r.stdout)
    assert "summary" in data and "findings" in data
    assert len(data["findings"]) >= 1


def test_json_attack_graph(dirty: Path) -> None:
    r = _run(dirty, "--format", "json", "--attack-graph")
    assert "graph" in json.loads(r.stdout)


def test_sarif_structure(dirty: Path) -> None:
    data = json.loads(_run(dirty, "--format", "sarif").stdout)
    assert "2.1.0" in data.get("$schema", "")
    assert data.get("runs")


def test_html_structure(dirty: Path) -> None:
    assert _run(dirty, "--format", "html").stdout.lower().startswith("<!doctype html>")


def test_text_structure(dirty: Path) -> None:
    r = _run(dirty, "--format", "text")
    assert r.stdout.startswith("# tf-analyze:")


@pytest.mark.parametrize("fmt,extra", [
    ("mitre", []),
    ("compliance", ["--compliance"]),
    ("pr-summary", []),
])
def test_other_formats_run(dirty: Path, fmt: str, extra: list) -> None:
    r = _run(dirty, "--format", fmt, *extra)
    assert r.returncode in (0, 1), r.stderr
    assert r.stdout.strip()


def test_show_fixes_and_show_info_text(dirty: Path) -> None:
    r = _run(dirty, "--format", "text", "--show-fixes", "--show-info")
    assert r.returncode in (0, 1), r.stderr
    assert r.stdout.startswith("# tf-analyze:")


# --------------------------------------------------------------------------- #
# --compare delta branch
# --------------------------------------------------------------------------- #
def test_compare_json_has_delta(dirty: Path, prior_json: Path) -> None:
    r = _run(dirty, "--format", "json", "--compare", str(prior_json))
    assert "delta" in json.loads(r.stdout)


def test_compare_text_runs(dirty: Path, prior_json: Path) -> None:
    r = _run(dirty, "--format", "text", "--compare", str(prior_json))
    assert r.returncode in (0, 1), r.stderr
    assert r.stdout.startswith("# tf-analyze:")


# --------------------------------------------------------------------------- #
# --fail-on exit code (the tail after rendering)
# --------------------------------------------------------------------------- #
def test_fail_on_returns_1_when_findings(dirty: Path) -> None:
    # The fixture yields HIGH/CRITICAL findings, so --fail-on HIGH must exit 1.
    assert _run(dirty, "--format", "text", "--fail-on", "HIGH").returncode == 1
