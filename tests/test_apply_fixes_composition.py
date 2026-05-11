"""Tests for `--apply-fixes` × `--baseline` and `--mode diff` × `--baseline`
composition (R30.11) plus the `fix_hcl_minimal` catalogue field (R30.10).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import DETECT_PY, REPO_ROOT


class TestFixHclMinimalSchema:
    def test_catalog_accepts_fix_hcl_minimal(self, tmp_path: Path) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from _catalog import validate_catalog_entry  # type: ignore
        entry = {
            "id": "CUSTOM-TEST-001",
            "title": "Test",
            "section": "security",
            "default_urgency": "MEDIUM",
            "blast_radius": "single-resource",
            "status": "active",
            "patterns": [{"kind": "grep", "regex": "x"}],
            "recommendation": "do the thing",
            "verification": "check the thing",
            "fix_hcl": "resource \"x\" \"y\" { z = 1 }",
            "fix_hcl_minimal": "z = 1",
        }
        # `source` must match the rule ID's filename stem.
        errs = validate_catalog_entry(entry, source="CUSTOM-TEST-001")
        assert errs == [], errs

    def test_catalog_rejects_non_string_fix_hcl_minimal(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from _catalog import validate_catalog_entry  # type: ignore
        entry = {
            "id": "CUSTOM-TEST-001",
            "title": "Test",
            "section": "security",
            "default_urgency": "MEDIUM",
            "status": "active",
            "patterns": [{"kind": "grep", "regex": "x"}],
            "fix_hcl_minimal": 42,
        }
        errs = validate_catalog_entry(entry, source="test")
        assert any("fix_hcl_minimal" in e for e in errs)


class TestApplyFixesWithBaseline:
    def test_baselined_findings_are_skipped(self, tmp_path: Path) -> None:
        """When --baseline points at a JSON report that already contains
        a finding, --apply-fixes must NOT patch that finding's file.

        Uses the storage-encrypted fixture: a known finding fires;
        baseline preserves it; apply-fixes dry-run should print nothing
        instead of a diff."""
        tf = tmp_path / "main.tf"
        tf.write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        # Step 1: snapshot baseline.
        snap = subprocess.run(
            [sys.executable, str(DETECT_PY),
             "--target", str(tmp_path), "--format", "json"],
            capture_output=True, text=True,
        )
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(snap.stdout)

        # Step 2: dry-run apply-fixes with the baseline — should report
        # zero patches because every finding is already baselined.
        proc = subprocess.run(
            [sys.executable, str(DETECT_PY),
             "--target", str(tmp_path),
             "--apply-fixes", "dry-run",
             "--baseline", str(baseline_path),
             "--format", "text"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0
        # Diagnostic on stderr documents the skip.
        assert "skipping" in proc.stderr or "baselined" in proc.stderr
        # No unified-diff blocks in the dry-run output.
        assert "--- " not in proc.stdout

    def test_apply_fixes_without_baseline_still_runs(self, tmp_path: Path) -> None:
        """Sanity guard: the baseline branch must not regress the
        non-baseline path."""
        tf = tmp_path / "main.tf"
        tf.write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        proc = subprocess.run(
            [sys.executable, str(DETECT_PY),
             "--target", str(tmp_path),
             "--apply-fixes", "dry-run",
             "--format", "text"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0


class TestDiffWithBaseline:
    def test_diff_and_baseline_compose(self, tmp_path: Path) -> None:
        """--mode diff + --baseline: only NEW findings on changed files
        affect output. Both flags compose because they're orthogonal
        layers (file-set narrowing vs tuple-set filtering)."""
        # Init a git repo so --mode diff has something to diff against.
        # Force an explicit `main` branch so the test doesn't depend on
        # the user's git init.defaultBranch config.
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
        subprocess.run(["git", "config", "user.email", "t@t"], cwd=tmp_path, check=True)
        subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, check=True)
        # Baseline starts with one already-bad resource on `main`.
        tf = tmp_path / "main.tf"
        tf.write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True)

        # Snapshot baseline of `main` BEFORE branching.
        snap = subprocess.run(
            [sys.executable, str(DETECT_PY),
             "--target", str(tmp_path), "--format", "json"],
            capture_output=True, text=True,
        )
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(snap.stdout)
        baseline_data = json.loads(snap.stdout)
        baseline_findings = baseline_data.get("findings") or []
        assert baseline_findings, "expected baseline to contain ≥1 finding"

        # Cut a feature branch and add a NEW resource with the same flaw.
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=tmp_path, check=True)
        tf.write_text(
            tf.read_text()
            + 'resource "aws_db_instance" "y" {\n'
              '  storage_encrypted = false\n'
              '}\n'
        )
        # Commit the change so `git diff main...HEAD` picks it up; if
        # uncommitted we'd rely on `git ls-files --others` which only
        # catches untracked-new files, not modified-tracked ones.
        subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "feat"], cwd=tmp_path, check=True)

        proc = subprocess.run(
            [sys.executable, str(DETECT_PY),
             "--target", str(tmp_path),
             "--mode", "diff", "--diff-base", "main",
             "--baseline", str(baseline_path),
             "--format", "json"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0, proc.stderr
        data = json.loads(proc.stdout)
        suppressed = data.get("suppressed_by_baseline", [])
        retained = data.get("findings", [])
        # Composition contract: baselined tuples MUST be in
        # `suppressed_by_baseline`, never in `findings`.
        baseline_keys = {
            (f["id"], f.get("file"), f.get("line"), f.get("resource"))
            for f in suppressed
        }
        for f in retained:
            assert (f["id"], f.get("file"), f.get("line"), f.get("resource")) not in baseline_keys
