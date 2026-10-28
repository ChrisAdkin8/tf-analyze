"""ATT&CK tag precision gates.

A rule's `mitre:` list should name a technique only when the rule finds a
condition that directly enables that technique, or fails to stop it. A
review found tags spread far wider than that: T1195 "Supply Chain
Compromise" sat on 29 rules, including advice-only rules ("consider a
registry module") and end-of-life / deprecation checks. That inflated the
MITRE coverage badge and filled the `--format mitre` view with noise.

These tests stop that drift coming back:

* rules that are advice-only, or about old-but-pinned software, must not
  carry any T1195 tag — in the catalogue or in the `apply_mitre.py`
  manifest that can re-write the catalogue;
* the rules that really are about mutable dependencies keep T1195, so a
  later clean-up can't over-prune them;
* no single technique sits on more than `MAX_RULES_PER_TECHNIQUE` active
  rules. If a new rule legitimately pushes a technique past the cap,
  review the whole list for that technique before raising it.
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import apply_mitre  # noqa: E402
from detect import load_yaml  # noqa: E402

CATALOG_DIR = REPO_ROOT / "catalog"

# Set just above the post-review maximum (T1530 on 34 active rules).
MAX_RULES_PER_TECHNIQUE = 35

# Advice-only rules, and rules about old / EOL / deprecated software that is
# still pinned. None of them finds a dependency an attacker could swap, so
# none of them is T1195.
NO_SUPPLY_CHAIN_TAG = [
    "MOD-REUSE-AWS-VPC-001",
    "MOD-REUSE-AZURE-AKS-001",
    "MOD-REUSE-GCP-NETWORK-001",
    "MOD-STALE-001",
    "OPS-ENV-001",
    "ROB-VERSION-001",
    "ROB-VERSION-002",
    "SEC-K8S-SECRET-002",
    "STK-AZURE-AKS-VERSION-001",
    "STK-AZURE-FUNCTION-001",
    "STK-AZURE-MYSQL-EOL-001",
    "STK-AZURE-SQL-001",
    "STK-AZURE-VM-IMG-EOL-001",
    "STK-AZURE-WEBAPP-RUNTIME-001",
    "STK-GCP-CLOUDSQL-005",
    "STK-GCP-DEPRECATION-001",
    "STK-GCP-FUNCTIONS-001",
    "STK-GCP-GKE-RELEASE-001",
]

# Rules that find a mutable or unverified dependency. They keep T1195.
KEEPS_SUPPLY_CHAIN_TAG = [
    "MOD-PIN-001",
    "MOD-SUPPLY-001",
    "MOD-SUPPLY-003",
    "MOD-SUPPLY-004",
    "ROB-VERSION-003",
    "SEC-K8S-HELM-003",
    "SEC-SUPPLY-001",
]


def _load(rule_id: str) -> dict:
    return load_yaml((CATALOG_DIR / f"{rule_id}.yaml").read_text())


def _is_supply_chain(tag: object) -> bool:
    return str(tag).startswith("T1195")


@pytest.mark.parametrize("rule_id", NO_SUPPLY_CHAIN_TAG)
def test_advice_only_rule_has_no_t1195(rule_id: str) -> None:
    tags = _load(rule_id).get("mitre") or []
    assert not [t for t in tags if _is_supply_chain(t)], (
        f"{rule_id} carries a T1195 tag ({tags}) but does not detect a "
        "mutable or unverified dependency"
    )


@pytest.mark.parametrize("rule_id", NO_SUPPLY_CHAIN_TAG)
def test_manifest_does_not_re_add_t1195(rule_id: str) -> None:
    tags = apply_mitre.MITRE_MAPPINGS.get(rule_id, [])
    assert not [t for t in tags if _is_supply_chain(t)], (
        f"scripts/apply_mitre.py would write T1195 back onto {rule_id}"
    )


@pytest.mark.parametrize("rule_id", KEEPS_SUPPLY_CHAIN_TAG)
def test_dependency_rule_keeps_t1195(rule_id: str) -> None:
    tags = _load(rule_id).get("mitre") or []
    assert any(_is_supply_chain(t) for t in tags), (
        f"{rule_id} finds a mutable dependency and should keep T1195"
    )


def test_manifest_matches_catalogue() -> None:
    """Running `apply_mitre.py` must not change any rule's ATT&CK tags.

    The manifest replaces a rule's whole `mitre:` block, so a stale entry
    would silently undo a review like this one."""
    drift = {}
    for rule_id, tags in apply_mitre.MITRE_MAPPINGS.items():
        path = CATALOG_DIR / f"{rule_id}.yaml"
        if not path.exists():
            continue
        have = [str(t) for t in (load_yaml(path.read_text()).get("mitre") or [])]
        if have != list(tags):
            drift[rule_id] = (list(tags), have)
    assert not drift, f"apply_mitre.py manifest != catalogue (manifest, catalogue): {drift}"


def test_no_technique_is_on_too_many_rules() -> None:
    by_tech: dict[str, list[str]] = defaultdict(list)
    for p in sorted(CATALOG_DIR.glob("*.yaml")):
        d = load_yaml(p.read_text())
        if d.get("status") != "active":
            continue
        for t in d.get("mitre") or []:
            by_tech[str(t)].append(d.get("id", p.stem))
    over = {t: len(r) for t, r in by_tech.items() if len(r) > MAX_RULES_PER_TECHNIQUE}
    assert not over, (
        f"techniques on more than {MAX_RULES_PER_TECHNIQUE} active rules: {over}. "
        "Review each rule against the technique's ATT&CK definition before "
        "raising the cap."
    )
