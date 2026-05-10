"""Tests for the post-MITRE-sweep follow-up work:

- SARIF v2.1 `taxonomies` + per-rule `relationships` (proper structured
  taxonomy emission, complementing the existing flat `cwe:CWE-732` tags)
- The MITRE module refactor (`scripts/_mitre.py` is the new home;
  `detect.py` re-exports for backward compat)
- The ATT&CK drift-check script

These pin contracts that consumers (GitHub Code Scanning, downstream
SIEMs, the CI drift gate) rely on.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from helpers import DETECT_PY, REPO_ROOT


# ---- Refactor: _mitre module is the single source of truth ----------------

class TestMitreModule:
    def test_mitre_module_imports_cleanly(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import _mitre
        # Public surface — what detect.py and the drift-check script depend on.
        assert hasattr(_mitre, "MITRE_ATTACK_VERSION")
        assert hasattr(_mitre, "MITRE_TECHNIQUE_INFO")
        assert hasattr(_mitre, "MITRE_TACTIC_ORDER")
        assert hasattr(_mitre, "mitre_technique_name")
        assert hasattr(_mitre, "mitre_technique_tactics")

    def test_detect_re_exports_from_mitre(self) -> None:
        """detect.py keeps the legacy `_MITRE_*` private aliases pointing
        at the new module — no external caller has to migrate."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        import _mitre
        # Same dict object, not a copy — confirms the re-export is a
        # binding, not a stale snapshot.
        assert detect._MITRE_TECHNIQUE_INFO is _mitre.MITRE_TECHNIQUE_INFO
        assert detect._MITRE_TACTIC_ORDER is _mitre.MITRE_TACTIC_ORDER
        assert detect.MITRE_ATTACK_VERSION == _mitre.MITRE_ATTACK_VERSION

    def test_helpers_round_trip(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from _mitre import mitre_technique_name, mitre_technique_tactics
        assert mitre_technique_name("T1078.004") == "Valid Accounts: Cloud Accounts"
        assert "Initial Access" in mitre_technique_tactics("T1190")
        # Unknown technique falls back gracefully — empty name, 'Other' tactic.
        assert mitre_technique_name("T9999") == ""
        assert mitre_technique_tactics("T9999") == ["Other"]


# ---- ATT&CK drift gate ----------------------------------------------------

class TestAttackDriftGate:
    @pytest.fixture(scope="class")
    def drift_output(self) -> tuple[int, str]:
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "check_attack_drift.py")],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        return result.returncode, result.stdout + result.stderr

    def test_drift_check_passes_on_current_catalogue(self, drift_output: tuple[int, str]) -> None:
        code, out = drift_output
        assert code == 0, f"Drift check failed:\n{out}"

    def test_drift_check_reports_attack_version(self, drift_output: tuple[int, str]) -> None:
        _, out = drift_output
        assert "ATT&CK pin: v" in out

    def test_drift_check_summary_present(self, drift_output: tuple[int, str]) -> None:
        _, out = drift_output
        assert "OK: catalogue and table are in sync" in out


# ---- SARIF v2.1 taxonomies + relationships --------------------------------

class TestSarifTaxonomies:
    @pytest.fixture(scope="class")
    def sarif(self) -> dict:
        result = subprocess.run(
            [sys.executable, str(DETECT_PY),
             "--target", str(REPO_ROOT / "examples/terragoat"),
             "--format", "sarif"],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        return json.loads(result.stdout)

    def test_run_declares_supported_taxonomies(self, sarif: dict) -> None:
        run = sarif["runs"][0]
        names = [t["name"] for t in run["tool"]["driver"].get("supportedTaxonomies", [])]
        # All four taxonomies should be declared because terragoat carries
        # mappings across the catalogue.
        assert {"CWE", "MITRE-ATT&CK", "MITRE-D3FEND", "CIS"} <= set(names)

    def test_taxonomies_array_present_with_taxa(self, sarif: dict) -> None:
        run = sarif["runs"][0]
        taxonomies = run.get("taxonomies", [])
        assert len(taxonomies) >= 4
        for t in taxonomies:
            assert "name" in t
            assert "guid" in t
            assert "informationUri" in t
            assert isinstance(t.get("taxa"), list) and len(t["taxa"]) > 0
            # Every taxon needs at least an id and a name.
            for taxon in t["taxa"]:
                assert taxon.get("id"), f"taxon missing id in {t['name']}: {taxon}"
                assert taxon.get("name"), f"taxon missing name in {t['name']}: {taxon}"

    def test_cwe_taxonomy_uses_canonical_id_form(self, sarif: dict) -> None:
        run = sarif["runs"][0]
        cwe_block = next(t for t in run["taxonomies"] if t["name"] == "CWE")
        # SARIF taxa.id for CWE is the bare numeric ID (matches OASIS
        # SARIF examples and CodeQL's emission). The display name keeps
        # the 'CWE-' prefix.
        for taxon in cwe_block["taxa"]:
            assert taxon["id"].isdigit(), f"CWE taxon id should be bare digits: {taxon}"
            assert taxon["name"].startswith("CWE-"), f"CWE taxon name should be 'CWE-N': {taxon}"

    def test_mitre_taxonomy_includes_human_names(self, sarif: dict) -> None:
        """MITRE-ATT&CK taxa shortDescription should be the technique's
        human name (e.g., 'Valid Accounts: Cloud Accounts'), not the
        bare ID. Without this, downstream consumers have to do their
        own ATT&CK lookup."""
        run = sarif["runs"][0]
        mitre_block = next(t for t in run["taxonomies"] if t["name"] == "MITRE-ATT&CK")
        names = {taxon["id"]: taxon["shortDescription"]["text"] for taxon in mitre_block["taxa"]}
        # If T1078.004 is referenced (it is — many AWS IAM rules), it
        # should have its proper name.
        if "T1078.004" in names:
            assert names["T1078.004"] == "Valid Accounts: Cloud Accounts"

    def test_rules_have_relationships(self, sarif: dict) -> None:
        run = sarif["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        rules_with_rels = [r for r in rules if r.get("relationships")]
        # Most rules carry at least one taxonomy reference now.
        assert len(rules_with_rels) >= 100, (
            f"only {len(rules_with_rels)} rules have relationships — "
            "did the taxonomy emit regress?"
        )

    def test_relationships_target_declared_taxonomies(self, sarif: dict) -> None:
        run = sarif["runs"][0]
        declared = {t["name"] for t in run["taxonomies"]}
        rules = run["tool"]["driver"]["rules"]
        for r in rules:
            for rel in r.get("relationships") or []:
                tc = rel["target"].get("toolComponent", {})
                assert tc.get("name") in declared, (
                    f"rule {r['id']} references undeclared taxonomy "
                    f"{tc.get('name')!r}"
                )

    def test_d3fend_relationships_use_incomparable_kind(self, sarif: dict) -> None:
        """D3FEND tags represent defensive countermeasures — semantically
        different from 'this rule indicates the named ATT&CK technique'.
        SARIF v2.1's `incomparable` kind is the right choice for that
        distinction; it tells consumers not to lump D3FEND and ATT&CK
        relationships together when filtering."""
        run = sarif["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        d3_rels_seen = False
        for r in rules:
            for rel in r.get("relationships") or []:
                if rel["target"].get("toolComponent", {}).get("name") == "MITRE-D3FEND":
                    assert rel.get("kinds") == ["incomparable"], (
                        f"D3FEND relationship on {r['id']} should use kinds=['incomparable'], "
                        f"got {rel.get('kinds')}"
                    )
                    d3_rels_seen = True
        assert d3_rels_seen, "no D3FEND relationships in SARIF — sweep regressed?"

    def test_flat_tags_still_emitted_for_backward_compat(self, sarif: dict) -> None:
        """Old consumers filter by flat `cwe:CWE-N` tags. New taxonomies
        block is additive; flat tags must remain."""
        run = sarif["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        sample = next((r for r in rules if r["id"] == "SEC-AWS-IAM-001"), None)
        assert sample is not None
        tags = sample["properties"]["tags"]
        assert any(t.startswith("cwe:CWE-") for t in tags)
        assert any(t.startswith("mitre:T") for t in tags)
        assert any(t.startswith("d3fend:D3-") for t in tags)
