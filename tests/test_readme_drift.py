"""README claim drift guard.

The top-level README has hand-maintained badges + a comparison table
that have repeatedly drifted from the catalogue's actual state (95
audit findings closed over five rounds; the fix_hcl-coverage and
framework-count claims were the most-recent example to drift in
silently). This test parses each load-bearing claim out of README.md
and asserts it matches the live catalogue + docs.

When a claim drifts, the test prints the expected value and the line
in README.md to update. It will fail; updating the README is the
fix — these are *not* allowed to be auto-rewritten by the test
itself, because the README is the document the project advertises
to outsiders and silent edits would break the audit trail.

Numbers gated here (kept narrow — only the ones we've burned on):
  * Rules: <N>          shields-badge — count of active catalog/*.yaml
  * fix_hcl: <N>%       shields-badge — % of active rules with fix_hcl
  * rule docs - <N> pages   shields-badge — count of docs/rules/*.md
  * Comparison-table "**<N>** (with real per-rule data)" frameworks
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
README = REPO_ROOT / "README.md"
CATALOG_DIR = REPO_ROOT / "catalog"
RULE_DOCS_DIR = REPO_ROOT / "docs" / "rules"


def _active_entries() -> list[dict]:
    """Load every catalog/*.yaml that isn't tagged status: deprecated."""
    out: list[dict] = []
    for yml in CATALOG_DIR.glob("*.yaml"):
        try:
            d = yaml.safe_load(yml.read_text())
        except yaml.YAMLError:
            continue
        if d.get("status") == "deprecated":
            continue
        out.append(d)
    return out


def _readme_text() -> str:
    return README.read_text()


# ---- helpers — compute live values from the source of truth -------------

def _active_rule_count() -> int:
    return len(_active_entries())


def _fix_hcl_percent() -> int:
    """Return integer percent (0..100) of active rules with non-empty fix_hcl."""
    ents = _active_entries()
    if not ents:
        return 0
    with_fix = sum(1 for d in ents if d.get("fix_hcl"))
    return with_fix * 100 // len(ents)


def _rule_doc_count() -> int:
    """Count per-rule pages under docs/rules/. index.md is the listing
    page and is excluded — the badge counts published rule docs, not
    the index entry."""
    pages = [p for p in RULE_DOCS_DIR.glob("*.md") if p.name != "index.md"]
    return len(pages)


def _frameworks_with_data() -> set[str]:
    """Return the set of framework names that have ≥1 tagged rule.

    Mirrors what `_output.py` ships as a `--compliance-framework`
    choice. A framework with zero tagged rules is a CLI flag stub —
    it's allowed to exist, but it doesn't count toward the
    "frameworks with real per-rule data" comparison-table number.
    """
    counts: dict[str, int] = {}
    # Top-level YAML fields where a non-empty value means the rule is
    # tagged for that framework.
    field_frameworks = {
        "cis": "cis",
        "pci_dss": "pci_dss",
        "soc2_cc": "soc2",
        "owasp_iac": "owasp_iac",
        "nist_csf": "nist_csf",
        "nist_800_53": "nist_800_53",
        "csa_ccm": "csa_ccm",
        "slsa": "slsa",
    }
    # Sub-namespaces hidden inside the `owasp:` list of `<prefix><id>` tags.
    owasp_prefix_frameworks = {
        "owasp_top10": re.compile(r"A(?:0[1-9]|10)\b"),
        "owasp_api":   re.compile(r"API\d"),
        "owasp_cicd":  re.compile(r"CICD-?\d"),
        "owasp_llm":   re.compile(r"LLM\d"),
        "owasp_k8s":   re.compile(r"K\d"),
        "owasp_asvs":  re.compile(r"V\d"),
    }
    for ent in _active_entries():
        for field, fw_name in field_frameworks.items():
            if ent.get(field):
                counts[fw_name] = counts.get(fw_name, 0) + 1
        for tag in ent.get("owasp") or []:
            for fw_name, rgx in owasp_prefix_frameworks.items():
                if rgx.match(str(tag)):
                    counts[fw_name] = counts.get(fw_name, 0) + 1
                    break
    return {fw for fw, n in counts.items() if n > 0}


# ---- tests --------------------------------------------------------------

_BADGE_RE = {
    "rules":      re.compile(r"!\[Rules:\s*(\d+)\]\(https://img\.shields\.io/badge/rules-(\d+)-"),
    "fix_hcl":    re.compile(r"!\[fix_hcl:\s*(\d+)%\]\(https://img\.shields\.io/badge/fix__hcl-(\d+)%25-"),
    "rule_docs":  re.compile(r"!\[Rule docs\]\(https://img\.shields\.io/badge/rule%20docs-(\d+)%20pages-"),
}


def test_readme_rules_badge_matches_catalog() -> None:
    """The `Rules: N` badge must match `len(active catalog/*.yaml)`."""
    m = _BADGE_RE["rules"].search(_readme_text())
    assert m, "README.md is missing the 'Rules: N' shield badge — re-add it (see line ~18)"
    label_n, url_n = int(m.group(1)), int(m.group(2))
    assert label_n == url_n, (
        f"README rules badge label ({label_n}) and URL ({url_n}) disagree — "
        "update both to the same number"
    )
    live = _active_rule_count()
    assert label_n == live, (
        f"README rules badge says {label_n}, catalogue has {live} active rules. "
        f"Edit the badge near README.md line ~18 to match."
    )


def test_readme_fix_hcl_badge_matches_catalog() -> None:
    """The `fix_hcl: N%` badge must match the live coverage rounded down."""
    m = _BADGE_RE["fix_hcl"].search(_readme_text())
    assert m, "README.md is missing the 'fix_hcl: N%' shield badge — re-add it (see line ~19)"
    label_pct, url_pct = int(m.group(1)), int(m.group(2))
    assert label_pct == url_pct, (
        f"README fix_hcl badge label ({label_pct}%) and URL ({url_pct}%) disagree — "
        "update both to the same number"
    )
    live = _fix_hcl_percent()
    # Allow ±1 to tolerate rounding when a single rule is added/removed.
    assert abs(label_pct - live) <= 1, (
        f"README fix_hcl badge says {label_pct}%, catalogue is at {live}%. "
        f"Edit the badge near README.md line ~19 to match (or backfill fix_hcl entries "
        f"on the remaining {100 - live}% of rules)."
    )


def test_readme_rule_docs_badge_matches_docs_dir() -> None:
    """The `rule docs - N pages` badge must match the count of
    per-rule .md files under docs/rules/."""
    m = _BADGE_RE["rule_docs"].search(_readme_text())
    assert m, "README.md is missing the 'rule docs - N pages' shield badge"
    badge_n = int(m.group(1))
    live = _rule_doc_count()
    assert badge_n == live, (
        f"README rule-docs badge says {badge_n} pages, docs/rules/ has {live} "
        f"(excluding index.md). Edit the badge near README.md line ~23 to match, "
        f"or re-run `python3 scripts/gen_rule_docs.py` if the docs are stale."
    )


_FRAMEWORK_TABLE_RE = re.compile(
    r"Compliance frameworks shipped \(with real per-rule data\)\s*\|\s*\*\*(\d+)\*\*"
)


def test_readme_compliance_framework_count_matches_catalog() -> None:
    """The comparison-table 'frameworks with real per-rule data' bold
    number must match the count of CLI framework choices that actually
    have ≥1 tagged rule in the catalogue."""
    m = _FRAMEWORK_TABLE_RE.search(_readme_text())
    assert m, (
        "README.md comparison table no longer contains the "
        "'Compliance frameworks shipped (with real per-rule data) | **N**' row. "
        "Either restore the row or update this test."
    )
    claimed = int(m.group(1))
    live = len(_frameworks_with_data())
    assert claimed == live, (
        f"README comparison table claims {claimed} compliance frameworks "
        f"with per-rule data; catalogue actually has {live}. "
        f"Edit the bold number in the comparison table (~README.md:123) to match. "
        f"Frameworks with data right now: {sorted(_frameworks_with_data())}"
    )
