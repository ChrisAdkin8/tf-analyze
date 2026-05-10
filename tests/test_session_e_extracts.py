"""Tests for the Session-E modularisation extract: `_output.py`.

The functional contracts for SARIF / HTML / compliance / MITRE / PR
summary rendering are already covered by `tests/test_output_formats.py`,
`tests/test_sarif_taxonomies_and_refactor.py`, `tests/test_pr_summary.py`,
and `tests/test_compliance_owasp_iac.py` — all of which reach the
formatters via the `detect` module's re-export shim. These tests cover
the *seam contract* — that `_output.py` exposes the names callers
expect and that `detect.py` re-exports each name as a binding (not a
copy) so future renames stay in sync.

Same shape as the prior four session-contract test files
(`tests/test_session_{a,b,c,d}_extracts.py`).
"""
from __future__ import annotations

import sys

from helpers import REPO_ROOT


class TestOutputModule:
    def test_module_imports_cleanly(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import _output
        # Canonical URL constants
        assert hasattr(_output, "RULE_DOCS_URL_BASE")
        assert hasattr(_output, "SARIF_HELP_URI_BASE")
        # Data tables
        assert hasattr(_output, "_ATTACK_NARRATIVES")
        assert hasattr(_output, "_FIX_DISRUPTION_LABELS")
        # Functions — SARIF
        for n in ("_sarif_fingerprint", "_sarif_taxonomies",
                  "_sarif_rule_relationships", "to_sarif"):
            assert hasattr(_output, n), n
        # Functions — per-finding helpers
        for n in ("_effective_urgency", "_enrich_findings_for_output",
                  "_narrative_for_finding", "_disruption_badge"):
            assert hasattr(_output, n), n
        # Functions — HTML
        for n in ("_render_executive_view", "_render_fix_priority_html", "to_html"):
            assert hasattr(_output, n), n
        # Functions — compliance
        for n in ("_infer_cis_framework", "_compliance_gap_report",
                  "_render_compliance_text", "_render_compliance_html",
                  "_compliance_to_oscal"):
            assert hasattr(_output, n), n
        # Functions — MITRE + PR summary
        for n in ("_render_mitre", "_append_attack_graph_block",
                  "_render_pr_summary"):
            assert hasattr(_output, n), n

    def test_detect_re_exports_bindings_not_copies(self) -> None:
        """Every legacy `detect.<name>` symbol must be the same object
        as the one in `_output.py`. The `--format` dispatch in main()
        and the GitHub Action's `pr-summary` builder reach these
        through `detect.to_sarif` / `detect.to_html` /
        `detect._render_pr_summary`; if the shim ever decays into a
        copy, this catches it."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        import _output
        # Constants — `is` because the literal dict / str identity is
        # what the "single source of truth" contract requires.
        assert detect.RULE_DOCS_URL_BASE is _output.RULE_DOCS_URL_BASE
        assert detect.SARIF_HELP_URI_BASE is _output.SARIF_HELP_URI_BASE
        assert detect._ATTACK_NARRATIVES is _output._ATTACK_NARRATIVES
        assert detect._FIX_DISRUPTION_LABELS is _output._FIX_DISRUPTION_LABELS
        # Workhorse formatters — every `--format` mode goes through one
        # of these. Binding identity prevents a copy-by-value regression.
        for n in ("to_sarif", "to_html",
                  "_render_pr_summary", "_render_mitre",
                  "_compliance_gap_report", "_render_compliance_html",
                  "_compliance_to_oscal",
                  "_sarif_taxonomies", "_sarif_rule_relationships",
                  "_narrative_for_finding"):
            assert getattr(detect, n) is getattr(_output, n), (
                f"{n}: detect.{n} is NOT the same object as _output.{n} "
                f"— re-export shim decayed into a copy"
            )

    def test_cross_seam_imports_resolve(self) -> None:
        """`_output.py` imports `build_attack_graph`, `graph_to_mermaid`,
        `_render_graph_html` from `_attack_graph`, `MITRE_ATTACK_VERSION`
        from `_mitre`, and `validate_catalog_entry` from `_catalog`.
        Confirm each cross-seam edge is the same object on both
        sides — a regression here would make the formatters import
        stale copies."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import _output
        import _attack_graph
        import _mitre
        import _catalog
        assert _output.build_attack_graph is _attack_graph.build_attack_graph
        assert _output.graph_to_mermaid is _attack_graph.graph_to_mermaid
        assert _output._render_graph_html is _attack_graph._render_graph_html
        assert _output.MITRE_ATTACK_VERSION == _mitre.MITRE_ATTACK_VERSION
        assert _output.validate_catalog_entry is _catalog.validate_catalog_entry

    def test_round_trip_sarif_through_shim(self) -> None:
        """End-to-end: build SARIF on a tiny findings+entries fixture
        via the `detect` shim, confirm the standard SARIF v2.1
        envelope is present. Locks the contract that downstream
        consumers (GitHub Code Scanning, Azure DevOps, etc.) rely on."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        findings = [{
            "id": "SEC-AWS-IAM-001",
            "file": "main.tf",
            "line": 12,
            "resource": "aws_iam_role.demo",
            "urgency": "HIGH",
            "title": "Test rule for seam contract",
            "section": "security",
        }]
        entries = [{
            "id": "SEC-AWS-IAM-001",
            "title": "Test rule for seam contract",
            "section": "security",
            "default_urgency": "HIGH",
            "blast_radius": "module",
            "patterns": [{"kind": "grep", "regex": "x"}],
            "recommendation": "fix it",
            "verification": "check it",
        }]
        sarif = detect.to_sarif(findings, entries)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"]
        # The rule we synthesised must appear in driver.rules
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        assert "SEC-AWS-IAM-001" in rule_ids
        # And the finding must be in results
        assert len(run["results"]) == 1
        assert run["results"][0]["ruleId"] == "SEC-AWS-IAM-001"
        # helpUri must point at the canonical docs URL
        rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "SEC-AWS-IAM-001")
        assert rule["helpUri"] == "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-001/"

    def test_pr_summary_renders_through_shim(self) -> None:
        """`_render_pr_summary` is the GitHub Action's worked-example
        output. Lock the markdown shape at the seam — the action's
        `gh pr comment` step depends on the `## tf-analyze` header
        being the first line so it can dedupe comment edits."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        findings = [{
            "id": "SEC-AWS-IAM-001",
            "file": "main.tf",
            "line": 12,
            "resource": "aws_iam_role.demo",
            "urgency": "HIGH",
            "title": "Test rule",
            "section": "security",
        }]
        entries = [{
            "id": "SEC-AWS-IAM-001",
            "title": "Test rule",
            "section": "security",
            "default_urgency": "HIGH",
            "blast_radius": "module",
            "patterns": [{"kind": "grep", "regex": "x"}],
            "recommendation": "fix it",
            "verification": "check it",
        }]
        md = detect._render_pr_summary(findings, entries, summary={"score": 82, "grade": "B"})
        # Header — the GitHub Action's dedupe key
        assert md.startswith("##") or md.startswith("# ")
        # Must mention the rule we passed in
        assert "SEC-AWS-IAM-001" in md
