"""Contract tests for the per-rule documentation site at ``docs/rules/``.

Locks the relationship between the catalogue YAML and the generated
Markdown pages — every active rule has a doc, every doc points at a
real rule, and the generator is deterministic (re-running produces
byte-identical output).

Also asserts that the engine's link-target constants (`RULE_DOCS_URL_BASE`,
`SARIF_HELP_URI_BASE`) point at the doc site, so changing one without
the other is a test-fail tripwire.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
CATALOG_DIR = REPO_ROOT / "catalog"
DOCS_RULES_DIR = REPO_ROOT / "docs" / "rules"
GEN_SCRIPT = REPO_ROOT / "scripts" / "gen_rule_docs.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import detect  # noqa: E402
from detect import load_yaml  # noqa: E402


def _active_rule_ids() -> set[str]:
    out: set[str] = set()
    for yml in sorted(CATALOG_DIR.glob("*.yaml")):
        try:
            data = load_yaml(yml.read_text())
        except Exception:
            continue
        if data.get("status") == "deprecated":
            continue
        if data.get("id"):
            out.add(data["id"])
    return out


# ---------------------------------------------------------------------------
# Coverage: catalogue ↔ docs
# ---------------------------------------------------------------------------


class TestRuleDocCoverage:
    def test_every_active_rule_has_a_docs_page(self):
        rule_ids = _active_rule_ids()
        missing = sorted(
            rid for rid in rule_ids
            if not (DOCS_RULES_DIR / f"{rid}.md").exists()
        )
        assert not missing, (
            f"{len(missing)} active rule(s) missing docs/rules/<id>.md. "
            f"Run `python3 scripts/gen_rule_docs.py`. First few: "
            f"{missing[:5]}"
        )

    def test_every_docs_page_corresponds_to_a_rule(self):
        # Stale doc files (rule was renamed/deleted) must be removed.
        rule_ids = _active_rule_ids()
        orphans = []
        for md in DOCS_RULES_DIR.glob("*.md"):
            if md.stem == "index":
                continue
            if md.stem not in rule_ids:
                orphans.append(md.stem)
        assert not orphans, (
            f"{len(orphans)} doc page(s) have no corresponding rule "
            f"(catalogue entry was renamed or deleted): {orphans[:5]}"
        )

    def test_index_page_exists(self):
        assert (DOCS_RULES_DIR / "index.md").exists(), (
            "docs/rules/index.md is missing — it's the public landing "
            "page for the rule reference. Run `gen_rule_docs.py`."
        )


# ---------------------------------------------------------------------------
# Generator determinism: re-running on the current catalogue must
# produce byte-identical output, otherwise the docs are drift-prone.
# ---------------------------------------------------------------------------


class TestGeneratorDeterminism:
    def test_check_mode_passes_on_current_catalogue(self):
        # `--check` exits 1 if any doc is stale relative to the catalogue.
        # If this fails, run `python3 scripts/gen_rule_docs.py` to rebuild.
        res = subprocess.run(
            [sys.executable, str(GEN_SCRIPT), "--check"],
            capture_output=True, text=True, timeout=60,
        )
        assert res.returncode == 0, (
            f"`gen_rule_docs.py --check` failed (exit {res.returncode}). "
            f"Stderr:\n{res.stderr}"
        )


# ---------------------------------------------------------------------------
# Engine link contract: detect.py constants point at the docs site.
# ---------------------------------------------------------------------------


class TestEngineLinkContract:
    def test_rule_docs_url_base_points_at_pages_site(self):
        assert "github.io/tf-analyze/rules" in detect.RULE_DOCS_URL_BASE, (
            f"RULE_DOCS_URL_BASE drifted: {detect.RULE_DOCS_URL_BASE!r}"
        )

    def test_sarif_help_uri_uses_the_same_base(self):
        # SARIF consumers (GitHub Code Scanning, Azure DevOps) follow
        # `helpUri`. Decoupling it from the docs site is a regression.
        assert detect.SARIF_HELP_URI_BASE == detect.RULE_DOCS_URL_BASE, (
            "SARIF_HELP_URI_BASE drifted from RULE_DOCS_URL_BASE — "
            "split URL targets confuse downstream consumers."
        )

    def test_url_template_includes_rule_id_placeholder(self):
        # The URL must be formattable with `{id}`.
        sample = detect.RULE_DOCS_URL_BASE.format(id="SEC-AWS-IAM-001")
        assert "SEC-AWS-IAM-001" in sample, (
            f"RULE_DOCS_URL_BASE doesn't substitute {{id}}: {sample!r}"
        )


# ---------------------------------------------------------------------------
# Compliance text + HTML carry the URL.
# ---------------------------------------------------------------------------


class TestComplianceLinkSurface:
    def test_compliance_text_emits_per_rule_url_for_failed_rules(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        res = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "detect.py"),
             "--target", str(tmp_path), "--format", "compliance",
             "--no-hcl2"],
            capture_output=True, text=True, timeout=60,
        )
        # Header line that explains the URL convention is always present.
        assert "github.io/tf-analyze/rules" in res.stdout, (
            "compliance text output should advertise the per-rule docs URL"
        )

    def test_compliance_html_wraps_rule_ids_as_anchors(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        res = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "detect.py"),
             "--target", str(tmp_path), "--format", "html", "--compliance",
             "--no-hcl2"],
            capture_output=True, text=True, timeout=60,
        )
        # At least one <a> with the docs URL must be present in compliance section.
        assert "github.io/tf-analyze/rules/" in res.stdout
        assert "<a href=" in res.stdout

    def test_findings_panel_rule_header_links_to_docs(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        res = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "detect.py"),
             "--target", str(tmp_path), "--format", "html",
             "--no-hcl2"],
            capture_output=True, text=True, timeout=60,
        )
        # Findings tab header must wrap the rule ID in an anchor.
        assert "title='Open rule documentation'" in res.stdout
        assert "github.io/tf-analyze/rules/" in res.stdout
