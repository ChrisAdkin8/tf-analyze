"""Tests for the workflow-YAML walker (R30.6).

Locks in three guarantees:
  * The walker discovers `.github/workflows/*.yml` files in addition to
    `*.tf` files when at least one catalogue rule declares the glob.
  * Catalogue rules with `not_regex:` on a `grep` pattern suppress when
    the negative pattern is present (used by SEC-CICD-001 / SEC-CICD-003
    to ignore properly-gated workflows).
  * `_collect_extra_files` de-duplicates and skips `.terraform/`.
"""
from __future__ import annotations

import sys
from pathlib import Path

from helpers import FIXTURES_DIR, REPO_ROOT, run_detect


class TestWalkerExtension:
    def test_workflow_yaml_loaded_into_corpus(self, tmp_path: Path) -> None:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "apply.yml").write_text(
            "jobs:\n  apply:\n    steps:\n      - run: terraform apply\n"
        )
        (tmp_path / "main.tf").write_text(
            'resource "null_resource" "placeholder" {}\n'
        )
        findings = run_detect(tmp_path, all_rules=True)
        fired = {f["id"] for f in findings}
        assert "SEC-CICD-001" in fired

    def test_environment_block_suppresses_via_not_regex(self, tmp_path: Path) -> None:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "apply.yml").write_text(
            "jobs:\n  apply:\n    environment:\n      name: production\n"
            "    steps:\n      - run: terraform apply\n"
        )
        (tmp_path / "main.tf").write_text(
            'resource "null_resource" "placeholder" {}\n'
        )
        findings = run_detect(tmp_path, all_rules=True)
        fired = {f["id"] for f in findings}
        assert "SEC-CICD-001" not in fired
        assert "SEC-CICD-003" not in fired

    def test_collect_extra_files_dedupes_and_skips_terraform_dir(
        self, tmp_path: Path
    ) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from detect import _collect_extra_files  # type: ignore

        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "a.yml").write_text("noop\n")
        (wf_dir / "b.yml").write_text("noop\n")
        # `.terraform/` cache must be excluded.
        cache_dir = tmp_path / ".terraform" / "modules" / "x" / ".github" / "workflows"
        cache_dir.mkdir(parents=True)
        (cache_dir / "c.yml").write_text("noop\n")

        # Mock entries — two rules pointing at the same glob to exercise dedupe.
        entries = [
            {
                "id": "MOCK-1",
                "patterns": [
                    {"kind": "grep", "file_glob": ".github/workflows/*.yml", "regex": "x"}
                ],
            },
            {
                "id": "MOCK-2",
                "patterns": [
                    {"kind": "grep", "file_glob": ".github/workflows/*.yml", "regex": "y"}
                ],
            },
        ]
        files = _collect_extra_files(tmp_path, entries)
        names = sorted(p.name for p in files)
        assert names == ["a.yml", "b.yml"]


class TestExistingFixturesLockIn:
    """Pin the three known-good positive fixtures + their clean pairs."""

    def test_workflow_apply_no_reviewers_fires_001_only(self) -> None:
        findings = run_detect(
            FIXTURES_DIR / "workflow_apply_no_reviewers",
            fixture_name="workflow_apply_no_reviewers",
        )
        assert {f["id"] for f in findings} == {"SEC-CICD-001"}

    def test_workflow_permissions_write_all_fires_002_only(self) -> None:
        findings = run_detect(
            FIXTURES_DIR / "workflow_permissions_write_all",
            fixture_name="workflow_permissions_write_all",
        )
        assert {f["id"] for f in findings} == {"SEC-CICD-002"}

    def test_workflow_auto_approve_no_env_fires_003_only(self) -> None:
        findings = run_detect(
            FIXTURES_DIR / "workflow_auto_approve_no_env",
            fixture_name="workflow_auto_approve_no_env",
        )
        assert {f["id"] for f in findings} == {"SEC-CICD-003"}
