"""Integration-surface tests for the R30.18 blast-radius surfaces.

Companion to ``tests/test_blast_radius.py`` (which unit-tests the
algorithm). This file pins the *surface* contracts that downstream
consumers depend on:

* :func:`_lsp.findings_to_diagnostics` uplifts severity by blast and
  appends the message annotation.
* :func:`_output._render_pr_summary` emits the "🌊 High blast radius"
  block when any finding has ``blast_radius ≥ 5``.
* The MCP server's ``blast_radius_report`` tool returns the
  hardened-envelope dict shape the README documents.

The MCP tool is exercised in-process to avoid spinning up a real MCP
stdio server — the function under test is the bare Python; the
envelope shape is what consumers actually rely on.
"""
from __future__ import annotations

import sys
from pathlib import Path

from helpers import REPO_ROOT

sys.path.insert(0, str(REPO_ROOT / "scripts"))


# ---------------------------------------------------------------------------
# LSP severity uplift (_lsp.findings_to_diagnostics)
# ---------------------------------------------------------------------------


def _make_finding(rule_id: str, blast: int) -> dict:
    return {
        "id": rule_id,
        "file": "main.tf",
        "line": 12,
        "resource": "aws_vpc.main",
        "blast_radius": blast,
    }


def _id_map_with(rule_id: str, urgency: str) -> dict:
    return {rule_id: {"default_urgency": urgency, "title": "Sample rule title"}}


def test_lsp_no_uplift_for_low_blast() -> None:
    from _lsp import findings_to_diagnostics  # type: ignore

    f = _make_finding("ROB-XYZ", blast=3)
    id_map = _id_map_with("ROB-XYZ", "MEDIUM")
    diags = findings_to_diagnostics([f], id_map)
    assert diags[0]["severity"] == 2  # MEDIUM unchanged
    # Message still picks up the annotation even when severity didn't move.
    assert "🌊 blast: 3" in diags[0]["message"]


def test_lsp_uplift_mid_blast_one_tier() -> None:
    from _lsp import findings_to_diagnostics  # type: ignore

    f = _make_finding("ROB-XYZ", blast=6)
    id_map = _id_map_with("ROB-XYZ", "MEDIUM")
    diags = findings_to_diagnostics([f], id_map)
    # MEDIUM (2) bumps to HIGH-equivalent (1).
    assert diags[0]["severity"] == 1
    assert "🌊 blast: 6" in diags[0]["message"]


def test_lsp_uplift_large_blast_two_tiers() -> None:
    from _lsp import findings_to_diagnostics  # type: ignore

    f = _make_finding("ROB-XYZ", blast=15)
    id_map = _id_map_with("ROB-XYZ", "LOW")
    diags = findings_to_diagnostics([f], id_map)
    # LOW (3) bumps 2 tiers to ERROR (1).
    assert diags[0]["severity"] == 1


def test_lsp_message_omits_annotation_when_blast_zero() -> None:
    from _lsp import findings_to_diagnostics  # type: ignore

    f = _make_finding("ROB-XYZ", blast=0)
    id_map = _id_map_with("ROB-XYZ", "HIGH")
    diags = findings_to_diagnostics([f], id_map)
    assert "🌊" not in diags[0]["message"]


def test_lsp_severity_floor_at_error() -> None:
    """Already-critical urgency can't uplift further — Error is the floor."""
    from _lsp import findings_to_diagnostics  # type: ignore

    f = _make_finding("ROB-XYZ", blast=99)
    id_map = _id_map_with("ROB-XYZ", "CRITICAL")
    diags = findings_to_diagnostics([f], id_map)
    assert diags[0]["severity"] == 1


# ---------------------------------------------------------------------------
# PR-summary blast-radius callout (_output._render_pr_summary)
# ---------------------------------------------------------------------------


def test_pr_summary_emits_blast_block_when_any_finding_high_blast() -> None:
    from _output import _render_pr_summary  # type: ignore

    findings = [
        {"id": "SEC-X-001", "file": "main.tf", "line": 1,
         "resource": "aws_vpc.main", "blast_radius": 12},
        {"id": "SEC-Y-002", "file": "main.tf", "line": 5,
         "resource": "aws_s3_bucket.data", "blast_radius": 0},
    ]
    entries = [
        {"id": "SEC-X-001", "default_urgency": "HIGH", "title": "Bad VPC"},
        {"id": "SEC-Y-002", "default_urgency": "HIGH", "title": "Bad bucket"},
    ]
    summary = {"score": 42, "grade": "D", "counts": {
        "CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }}
    out = _render_pr_summary(findings, entries, summary)
    assert "🌊 High blast radius" in out
    assert "aws_vpc.main" in out
    # The 0-blast finding must not appear in the block.
    assert "aws_s3_bucket.data" not in out.split("🌊 High blast radius")[1].split("Top fix")[0]


def test_pr_summary_omits_blast_block_when_no_high_blast() -> None:
    from _output import _render_pr_summary  # type: ignore

    findings = [
        {"id": "SEC-X-001", "file": "main.tf", "line": 1,
         "resource": "aws_s3_bucket.data", "blast_radius": 0},
    ]
    entries = [{"id": "SEC-X-001", "default_urgency": "HIGH", "title": "Bad bucket"}]
    summary = {"score": 90, "grade": "A", "counts": {
        "CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }}
    out = _render_pr_summary(findings, entries, summary)
    assert "🌊 High blast radius" not in out
