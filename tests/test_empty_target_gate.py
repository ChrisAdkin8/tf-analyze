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
    env = {
        **os.environ,
        "TFA_JSON_REPORT": str(tmp_path / "tf-analyze-findings.json"),
        "TFA_JSON_RC": "0",
        "TFA_FAIL_ON": "HIGH",
    }
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


# ---- unchecked input (critical review) ---------------------------------------------
# The engine fails --fail-on when a rule check runs out of time or a file
# can't be read. The Action gates its own report without --fail-on, so it
# has to read both from the summary, or a slow-to-match input turns a red
# PR green.


def _timeout_report(tmp_path: Path) -> dict:
    (tmp_path / "tf").mkdir()
    (tmp_path / "tf" / "main.tf").write_text(SSH_OPEN)
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "detect.py"), "--target",
         str(tmp_path / "tf"), "--format", "json"],
        capture_output=True, text=True, check=False,
        env={**os.environ, "TF_ANALYZE_PATTERN_TIMEOUT": "0.00001"},
    )
    report = json.loads(proc.stdout)
    assert report["summary"]["rule_timeouts"]
    return report


def _unreadable_report(tmp_path: Path) -> dict:
    (tmp_path / "tf").mkdir()
    (tmp_path / "tf" / "main.tf").write_text("locals {\n  x = 1\n}\n")
    # Not UTF-8 is no longer unreadable (bad bytes are replaced and the
    # file scanned); a file the scan has no permission to read still is.
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root can read a mode-000 file")
    (tmp_path / "tf" / "bad.tf").write_text("locals {}\n")
    (tmp_path / "tf" / "bad.tf").chmod(0)
    report = _engine_report(tmp_path / "tf")
    assert report["summary"]["unreadable_files"] == [str(tmp_path / "tf" / "bad.tf")]
    return report


def test_action_gate_fails_when_a_rule_check_timed_out(tmp_path) -> None:
    report = _timeout_report(tmp_path)
    report["findings"] = []  # the timed-out checks are what found them
    res = _gate(tmp_path, report)
    assert res.returncode == 1
    assert "ran out of time" in res.stderr


def test_action_gate_fails_when_a_file_could_not_be_read(tmp_path) -> None:
    res = _gate(tmp_path, _unreadable_report(tmp_path))
    assert res.returncode == 1
    assert "could not be read" in res.stderr


def _template_gate_script() -> str:
    text = (REPO / "integrations" / "github-action.yml").read_text()
    m = re.search(r'python3 -c "\n(.*?)\n\s*" \| tee', text, re.DOTALL)
    assert m, "template gate step no longer runs inline python3 -c"
    return m.group(1)


def _template_gate(tmp_path: Path, report: dict) -> subprocess.CompletedProcess:
    (tmp_path / "tf-analyze-findings.json").write_text(json.dumps(report))
    import textwrap

    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(_template_gate_script())],
        capture_output=True, text=True, cwd=tmp_path, check=False,
        env={**os.environ, "FAIL_ON": "HIGH", "OUT": str(tmp_path)},
    )


def test_template_gate_fails_on_unchecked_input(tmp_path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert _template_gate(tmp_path, _engine_report(empty)).returncode == 1
    assert _template_gate(tmp_path, _unreadable_report(tmp_path)).returncode == 1


def test_template_gate_passes_a_clean_scan(tmp_path) -> None:
    (tmp_path / "tf").mkdir()
    (tmp_path / "tf" / "main.tf").write_text("locals {\n  x = 1\n}\n")
    assert _template_gate(tmp_path, _engine_report(tmp_path / "tf")).returncode == 0
