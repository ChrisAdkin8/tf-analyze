"""Tests for the MITRE catalogue sweep + CWE + D3FEND fields and the
engine surface that renders them (`--format mitre` tactic grouping,
`--mitre-tactic` filter, SARIF taxonomy emission, schema validation).

These lock the contract on the round-29 MITRE/CWE/D3FEND work. Without
them, a future generator regression (or a removed `cwe:` field on a
catalogue entry) is invisible until it surfaces in production output.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import DETECT_PY, FIXTURES_DIR, REPO_ROOT

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import detect  # noqa: E402
from detect import load_yaml  # noqa: E402

CATALOG_DIR = REPO_ROOT / "catalog"


# ---- Catalogue coverage gates -----------------------------------------------

class TestCatalogCoverage:
    """Pin the headline coverage numbers documented in the round-29
    plan. If these regress, a recent commit removed a `mitre:` / `cwe:`
    / `d3fend:` field from a catalogue entry — investigate before
    accepting the lower number."""

    @pytest.fixture(scope="class")
    def active_rules(self) -> list[dict]:
        out = []
        for p in sorted(CATALOG_DIR.glob("*.yaml")):
            d = load_yaml(p.read_text())
            if d.get("status") == "deprecated":
                continue
            out.append(d)
        return out

    def test_mitre_coverage_above_floor(self, active_rules: list[dict]) -> None:
        mapped = sum(1 for d in active_rules if d.get("mitre"))
        # Round 29 sweep landed at 149/217 (69%). Floor at 60% gives
        # margin for catalogue churn but catches a regression of >20 rules.
        pct = 100 * mapped / len(active_rules)
        assert pct >= 60, f"MITRE coverage regressed to {pct:.0f}% ({mapped}/{len(active_rules)})"

    def test_cwe_coverage_above_floor(self, active_rules: list[dict]) -> None:
        mapped = sum(1 for d in active_rules if d.get("cwe"))
        pct = 100 * mapped / len(active_rules)
        assert pct >= 45, f"CWE coverage regressed to {pct:.0f}% ({mapped}/{len(active_rules)})"

    def test_d3fend_coverage_above_floor(self, active_rules: list[dict]) -> None:
        mapped = sum(1 for d in active_rules if d.get("d3fend"))
        pct = 100 * mapped / len(active_rules)
        assert pct >= 35, f"D3FEND coverage regressed to {pct:.0f}% ({mapped}/{len(active_rules)})"


# ---- Schema validation ------------------------------------------------------

class TestSchemaValidation:
    """The `cwe:` and `d3fend:` fields are validated by
    `validate_catalog_entry`. Wrong-shape values must fail catalogue
    load, not silently producing broken SARIF taxonomy output."""

    def test_cwe_must_be_canonical_form(self) -> None:
        from detect import validate_catalog_entry
        # Wrong forms
        for bad in ["cwe-732", "732", "CWE 732", "CWE_732"]:
            errs = validate_catalog_entry({
                "id": "TEST-001", "title": "x", "section": "security",
                "default_urgency": "MEDIUM", "blast_radius": "single-resource",
                "patterns": [{"kind": "grep"}],
                "recommendation": "x", "verification": "x",
                "cwe": [bad],
            }, "TEST-001.yaml")
            assert any("cwe" in e for e in errs), f"{bad!r} should fail validation: {errs}"
        # Right form
        errs = validate_catalog_entry({
            "id": "TEST-001", "title": "x", "section": "security",
            "default_urgency": "MEDIUM", "blast_radius": "single-resource",
            "patterns": [{"kind": "grep"}],
            "recommendation": "x", "verification": "x",
            "cwe": ["CWE-732", "CWE-269"],
        }, "TEST-001.yaml")
        assert not any("cwe" in e for e in errs), f"valid CWE list rejected: {errs}"

    def test_d3fend_must_match_id_form(self) -> None:
        from detect import validate_catalog_entry
        for bad in ["D3MFA", "D3-mfa", "MFA", "d3-mfa"]:
            errs = validate_catalog_entry({
                "id": "TEST-001", "title": "x", "section": "security",
                "default_urgency": "MEDIUM", "blast_radius": "single-resource",
                "patterns": [{"kind": "grep"}],
                "recommendation": "x", "verification": "x",
                "d3fend": [bad],
            }, "TEST-001.yaml")
            assert any("d3fend" in e for e in errs), f"{bad!r} should fail: {errs}"
        errs = validate_catalog_entry({
            "id": "TEST-001", "title": "x", "section": "security",
            "default_urgency": "MEDIUM", "blast_radius": "single-resource",
            "patterns": [{"kind": "grep"}],
            "recommendation": "x", "verification": "x",
            "d3fend": ["D3-MFA", "D3-EAR", "D3-CH"],
        }, "TEST-001.yaml")
        assert not any("d3fend" in e for e in errs), f"valid D3FEND list rejected: {errs}"


# ---- Engine: tactic grouping + technique names ------------------------------

class TestRenderMitre:
    """Lock the tactic-grouping output shape. Without this test a
    refactor to alphabetical-by-ID grouping (the pre-round-29 shape)
    would silently revert the SOC-readable layout."""

    @pytest.fixture(scope="class")
    def mitre_output(self) -> str:
        result = subprocess.run(
            [sys.executable, str(DETECT_PY),
             "--target", str(REPO_ROOT / "examples/terragoat"),
             "--format", "mitre"],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        return result.stdout

    def test_header_pins_attack_version(self, mitre_output: str) -> None:
        assert detect.MITRE_ATTACK_VERSION in mitre_output
        assert "MITRE ATT&CK Coverage" in mitre_output

    def test_groups_by_tactic_h2(self, mitre_output: str) -> None:
        # Initial Access should appear as an H3 ('### Initial Access') —
        # the canonical kill-chain order means Reconnaissance / Resource
        # Development / Initial Access come early.
        assert "### Initial Access" in mitre_output
        assert "### Defense Evasion" in mitre_output
        assert "### Impact" in mitre_output

    def test_emits_technique_names_not_just_ids(self, mitre_output: str) -> None:
        # Bare 'T1078.004' alone (no name) would mean the dictionary lookup
        # broke. Look for the en-dash + name format.
        assert "T1078.004 — Valid Accounts: Cloud Accounts" in mitre_output
        assert "T1530 — Data from Cloud Storage" in mitre_output

    def test_tactic_filter_restricts_output(self) -> None:
        result = subprocess.run(
            [sys.executable, str(DETECT_PY),
             "--target", str(REPO_ROOT / "examples/terragoat"),
             "--format", "mitre", "--mitre-tactic", "initial-access"],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        out = result.stdout
        assert "### Initial Access" in out
        # Other tactics must be absent when filtered.
        assert "### Defense Evasion" not in out
        assert "### Impact" not in out

    def test_tactic_filter_is_case_insensitive_and_separator_tolerant(self) -> None:
        # 'Initial Access', 'initial-access', 'initial_access' all equivalent.
        outs = []
        for variant in ("Initial Access", "initial-access", "initial_access", "INITIAL_ACCESS"):
            r = subprocess.run(
                [sys.executable, str(DETECT_PY),
                 "--target", str(REPO_ROOT / "examples/terragoat"),
                 "--format", "mitre", "--mitre-tactic", variant],
                capture_output=True, text=True, cwd=REPO_ROOT,
            )
            outs.append(r.stdout)
        # Every variant should produce non-empty output containing 'Initial Access'.
        for o in outs:
            assert "### Initial Access" in o, "tactic filter rejected a valid variant"


# ---- SARIF taxonomies (flat-tag form) ---------------------------------------

class TestSarifTaxonomies:
    """SARIF rules emit cwe:* / d3fend:* tags alongside the existing
    cis:*/mitre:* tags. GitHub Code Scanning and Azure DevOps both
    consume these as filterable tags."""

    @pytest.fixture(scope="class")
    def sarif(self) -> dict:
        result = subprocess.run(
            [sys.executable, str(DETECT_PY),
             "--target", str(REPO_ROOT / "examples/terragoat"),
             "--format", "sarif"],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        return json.loads(result.stdout)

    def test_sarif_tags_include_cwe(self, sarif: dict) -> None:
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        # At least one rule should have a cwe:CWE-NNN tag — terragoat hits
        # SEC-AWS-IAM-001 which carries CWE-269 + CWE-732 post-sweep.
        all_tags: set[str] = set()
        for r in rules:
            for tag in r.get("properties", {}).get("tags", []):
                all_tags.add(tag)
        cwe_tags = {t for t in all_tags if t.startswith("cwe:")}
        assert len(cwe_tags) >= 5, f"too few CWE tags in SARIF: {cwe_tags}"

    def test_sarif_tags_include_d3fend(self, sarif: dict) -> None:
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        all_tags: set[str] = set()
        for r in rules:
            for tag in r.get("properties", {}).get("tags", []):
                all_tags.add(tag)
        d3_tags = {t for t in all_tags if t.startswith("d3fend:")}
        assert len(d3_tags) >= 3, f"too few D3FEND tags in SARIF: {d3_tags}"

    def test_sarif_d3fend_tags_use_canonical_form(self, sarif: dict) -> None:
        """Tag values must be 'd3fend:D3-<TOKEN>' (preserves the case
        consumers expect for cross-referencing the d3fend.mitre.org
        ontology)."""
        import re
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for r in rules:
            for tag in r.get("properties", {}).get("tags", []):
                if tag.startswith("d3fend:"):
                    val = tag.removeprefix("d3fend:")
                    assert re.fullmatch(r"D3-[A-Z]{2,8}", val), \
                        f"non-canonical d3fend tag in SARIF: {tag!r}"


# ---- Per-rule docs render the new blocks -----------------------------------

class TestRuleDocsCWED3fend:
    DOCS_DIR = REPO_ROOT / "docs" / "rules"
    SAMPLE = "SEC-AWS-IAM-001"  # has mitre + cwe + d3fend post-sweep

    def test_cwe_block_rendered(self) -> None:
        page = (self.DOCS_DIR / f"{self.SAMPLE}.md").read_text()
        assert "**CWE**" in page
        # Bullet-list form with bracketed link to cwe.mitre.org
        assert "https://cwe.mitre.org/data/definitions/" in page

    def test_d3fend_block_rendered(self) -> None:
        page = (self.DOCS_DIR / f"{self.SAMPLE}.md").read_text()
        assert "**MITRE D3FEND**" in page
        assert "https://d3fend.mitre.org/technique/D3-" in page

    def test_keywords_front_matter_includes_new_taxonomies(self) -> None:
        page = (self.DOCS_DIR / f"{self.SAMPLE}.md").read_text()
        head = page.split("---\n", 2)[1]
        # 'cwe-' (lowercase, hyphenated form for SEO keywords) and 'd3-'
        # appear in the keywords line.
        assert "cwe-" in head.lower()
        assert "d3-" in head.lower()
