"""Tests for custom rules support (#6)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from detect import load_catalog, detect_corpus, detect_in_file  # type: ignore

CATALOG_DIR = Path(__file__).parent.parent / "catalog"

CUSTOM_RULE_YAML = """\
id: CUSTOM-TEST-001
title: "Legacy t2 instance type"
section: ops
default_urgency: LOW
blast_radius: single-resource
status: active
patterns:
  - kind: resource_arg
    resource: aws_instance
    arg: instance_type
    regex: '^t2\\.'
    description: t2 instances are legacy; prefer t3 or later
recommendation: Upgrade to t3.micro
verification: Check instance type in AWS console
fix_hcl: |
  resource "aws_instance" "x" { instance_type = "t3.micro" }
fix_disruption: forces_replacement
fixtures: []
"""


def _run_full_scan(tmp_path: Path, entries: list) -> list:
    """Run both per-file and corpus-level detection."""
    all_files = {str(p): p.read_text() for p in tmp_path.rglob("*.tf")}
    findings = list(detect_corpus(tmp_path, all_files, entries))
    for fp, text in all_files.items():
        findings.extend(detect_in_file(Path(fp), text, entries))
    return findings


def test_custom_rule_fires(tmp_path: Path) -> None:
    rules_dir = tmp_path / ".tf-analyze-rules"
    rules_dir.mkdir()
    (rules_dir / "CUSTOM-TEST-001.yaml").write_text(CUSTOM_RULE_YAML)
    (tmp_path / "main.tf").write_text(
        'resource "aws_instance" "x" { instance_type = "t2.micro" }\n'
    )
    entries = load_catalog(CATALOG_DIR, extra_rules_dir=rules_dir)
    findings = _run_full_scan(tmp_path, entries)
    assert any(f["id"] == "CUSTOM-TEST-001" for f in findings), (
        f"Expected CUSTOM-TEST-001 to fire. Got: {sorted({f['id'] for f in findings})}"
    )


def test_ignore_rules_suppresses_finding(tmp_path: Path) -> None:
    rules_dir = tmp_path / ".tf-analyze-rules"
    rules_dir.mkdir()
    (rules_dir / "CUSTOM-TEST-001.yaml").write_text(CUSTOM_RULE_YAML)
    (tmp_path / "main.tf").write_text(
        'resource "aws_instance" "x" { instance_type = "t2.micro" }\n'
    )
    entries = load_catalog(CATALOG_DIR, extra_rules_dir=rules_dir)
    all_findings = _run_full_scan(tmp_path, entries)
    ignore = {"CUSTOM-TEST-001"}
    filtered = [f for f in all_findings if f["id"] not in ignore]
    assert not any(f["id"] == "CUSTOM-TEST-001" for f in filtered)


def test_custom_id_must_have_custom_prefix(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    bad_rule = (
        "id: BAD-001\ntitle: bad rule\nsection: ops\n"
        "default_urgency: LOW\nblast_radius: module\nstatus: active\n"
        "patterns: []\nrecommendation: x\nverification: x\nfixtures: []\n"
    )
    (rules_dir / "BAD-001.yaml").write_text(bad_rule)
    entries = load_catalog(CATALOG_DIR, extra_rules_dir=rules_dir)
    captured = capsys.readouterr()
    assert not any(e["id"] == "BAD-001" for e in entries), "BAD-001 should have been rejected"
    assert "CUSTOM-" in captured.err, f"Expected CUSTOM- warning in stderr, got: {captured.err!r}"
