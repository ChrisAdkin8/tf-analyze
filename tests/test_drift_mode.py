"""Tests for `--mode drift` (R30.12 — state-file scanning).

Locks in that:
  * `detect_in_state` reuses the plan-mode resource walker but tags
    findings with `mode='state'` and `file='<state>'`.
  * `--mode drift --state-json PATH` wires through detect.py's main()
    and emits findings.
  * `--mode drift` without `--state-json` exits 2 with a clear error.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import DETECT_PY, REPO_ROOT


sys.path.insert(0, str(REPO_ROOT / "scripts"))
from detect import detect_in_state, detect_in_plan  # type: ignore


def _state_with_unencrypted_rds(tmp_path: Path) -> Path:
    payload = {
        "format_version": "1.0",
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_db_instance.demo",
                        "mode": "managed",
                        "type": "aws_db_instance",
                        "name": "demo",
                        "values": {
                            "storage_encrypted": False,
                            "engine": "postgres",
                        },
                    }
                ]
            }
        },
    }
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps(payload))
    return state_path


def _plan_with_unencrypted_rds(tmp_path: Path) -> Path:
    payload = {
        "format_version": "1.0",
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_db_instance.demo",
                        "mode": "managed",
                        "type": "aws_db_instance",
                        "name": "demo",
                        "values": {
                            "storage_encrypted": False,
                            "engine": "postgres",
                        },
                    }
                ]
            }
        },
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(payload))
    return plan_path


class TestDetectInState:
    def test_returns_findings_tagged_as_state(self, tmp_path: Path) -> None:
        state_path = _state_with_unencrypted_rds(tmp_path)
        # Load real catalogue so the rule firing is a real signal.
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from detect import load_catalog  # type: ignore
        entries = load_catalog(REPO_ROOT / "catalog")
        findings = detect_in_state(state_path, entries)
        assert findings, "expected ≥1 finding against an unencrypted RDS state"
        for f in findings:
            assert f["mode"] == "state"
            assert f["file"] == "<state>"
            assert f["resource"].startswith("aws_db_instance")

    def test_drift_and_plan_share_the_resource_walker(self, tmp_path: Path) -> None:
        """Given identical resource trees, drift and plan must produce
        the same finding IDs (different `mode` tag, same detections).
        Regression-guards the `_evaluate_against_resources` refactor."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from detect import load_catalog  # type: ignore
        entries = load_catalog(REPO_ROOT / "catalog")
        state_findings = detect_in_state(_state_with_unencrypted_rds(tmp_path), entries)
        plan_findings = detect_in_plan(_plan_with_unencrypted_rds(tmp_path), entries)
        assert {f["id"] for f in state_findings} == {f["id"] for f in plan_findings}
        # Modes must differ — they're the disambiguator.
        assert {f["mode"] for f in state_findings} == {"state"}
        assert {f["mode"] for f in plan_findings} == {"plan"}

    def test_invalid_state_json_returns_empty(self, tmp_path: Path) -> None:
        bad = tmp_path / "broken.json"
        bad.write_text("not json")
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from detect import load_catalog  # type: ignore
        entries = load_catalog(REPO_ROOT / "catalog")
        assert detect_in_state(bad, entries) == []


class TestDriftCLI:
    def test_mode_drift_requires_state_json(self, tmp_path: Path) -> None:
        proc = subprocess.run(
            [sys.executable, str(DETECT_PY),
             "--target", str(tmp_path), "--mode", "drift"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 2
        assert "requires --state-json" in proc.stderr

    def test_mode_drift_with_state_emits_state_tagged_findings(
        self, tmp_path: Path,
    ) -> None:
        state_path = _state_with_unencrypted_rds(tmp_path)
        # Need a .tf file in the target dir for the walker not to bail.
        (tmp_path / "main.tf").write_text(
            'resource "null_resource" "placeholder" {}\n'
        )
        proc = subprocess.run(
            [sys.executable, str(DETECT_PY),
             "--target", str(tmp_path),
             "--mode", "drift",
             "--state-json", str(state_path),
             "--format", "json"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0, proc.stderr
        data = json.loads(proc.stdout)
        state_findings = [f for f in data["findings"] if f.get("mode") == "state"]
        assert state_findings, "expected ≥1 state-tagged finding"
        # Stderr should announce the count.
        assert "drift finding(s)" in proc.stderr

    def test_missing_state_file_exits_2(self, tmp_path: Path) -> None:
        proc = subprocess.run(
            [sys.executable, str(DETECT_PY),
             "--target", str(tmp_path),
             "--mode", "drift",
             "--state-json", str(tmp_path / "nope.json")],
            capture_output=True, text=True,
        )
        assert proc.returncode == 2
        assert "does not exist" in proc.stderr
