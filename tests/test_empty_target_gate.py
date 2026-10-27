"""A gated scan that found no Terraform fails instead of passing (critical
review): the engine exits 2 under ``--fail-on``, and the GitHub Action's
gate step fails on the report's ``nothing_scanned`` flag."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parents[1]
SSH_OPEN = (
    'resource "aws_security_group" "sg" {\n  ingress {\n    from_port   = 22\n'
    '    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
)


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO / "scripts" / "detect.py"), *args],
        capture_output=True,
        text=True,
        check=False,
    )


# ---- engine ----------------------------------------------------------------------


def test_gated_scan_of_an_empty_folder_exits_2(tmp_path) -> None:
    res = _run("--target", str(tmp_path), "--fail-on", "HIGH", "--format", "json")
    assert res.returncode == 2, res.stderr
    assert "nothing was checked" in res.stderr


def test_gated_scan_with_everything_ignored_exits_2(tmp_path) -> None:
    (tmp_path / "modules").mkdir()
    (tmp_path / "modules" / "main.tf").write_text("locals {\n  x = 1\n}\n")
    (tmp_path / ".tf-analyze.yaml").write_text("ignore_paths:\n  - modules\n")
    res = _run("--target", str(tmp_path), "--fail-on", "HIGH", "--format", "json")
    assert res.returncode == 2, res.stderr
    assert "after ignore_paths" in res.stderr


def test_ungated_scan_of_an_empty_folder_still_passes(tmp_path) -> None:
    res = _run("--target", str(tmp_path), "--format", "json")
    assert res.returncode == 0, res.stderr
    assert json.loads(res.stdout)["summary"]["nothing_scanned"] is True


def test_a_folder_with_terraform_but_no_findings_is_not_flagged(tmp_path) -> None:
    (tmp_path / "main.tf").write_text("locals {\n  x = 1\n}\n")
    res = _run("--target", str(tmp_path), "--fail-on", "HIGH", "--format", "json")
    assert res.returncode == 0, res.stderr
    assert "nothing_scanned" not in json.loads(res.stdout)["summary"]


# ---- GitHub Action gate step -----------------------------------------------------


def _gate_script() -> str:
    action = yaml.safe_load((REPO / "action.yml").read_text())
    step = next(
        s for s in action["runs"]["steps"] if s.get("name") == "Apply fail-on threshold"
    )
    m = re.search(r"<<'PY'\n(.*?)\n\s*PY\s*$", step["run"], re.DOTALL)
    assert m, "gate step no longer runs an inline Python heredoc"
    return m.group(1)


def _gate(tmp_path: Path, report: dict) -> subprocess.CompletedProcess:
    (tmp_path / "tf-analyze-findings.json").write_text(json.dumps(report))
    env = {**os.environ, "GITHUB_WORKSPACE": str(tmp_path), "TFA_FAIL_ON": "HIGH"}
    return subprocess.run(
        [sys.executable, "-c", _gate_script()],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _engine_report(target: Path) -> dict:
    return json.loads(_run("--target", str(target), "--format", "json").stdout)


def test_action_gate_fails_when_nothing_was_scanned(tmp_path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    res = _gate(tmp_path, _engine_report(empty))
    assert res.returncode == 1
    assert "nothing was checked" in res.stderr


def test_action_gate_passes_a_clean_scan(tmp_path) -> None:
    tf = tmp_path / "tf"
    tf.mkdir()
    (tf / "main.tf").write_text("locals {\n  x = 1\n}\n")
    assert _gate(tmp_path, _engine_report(tf)).returncode == 0


def test_action_gate_still_fails_on_findings(tmp_path) -> None:
    tf = tmp_path / "tf"
    tf.mkdir()
    (tf / "main.tf").write_text(SSH_OPEN)
    assert _gate(tmp_path, _engine_report(tf)).returncode == 1
