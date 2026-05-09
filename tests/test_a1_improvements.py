"""Tests for A1 detection improvements: ROB-DRIFT-002, ROB-FOREACH-002,
MOD-UNUSED-001, and the applies_when adoption sweep."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from helpers import DETECT_PY, FIXTURES_DIR, REPO_ROOT


def _run(target_dir: str | Path, *extra: str) -> dict:
    target = target_dir if isinstance(target_dir, Path) else FIXTURES_DIR / target_dir
    args = [
        sys.executable, str(DETECT_PY),
        "--target", str(target),
        "--format", "json",
        "--show-info",
        *extra,
    ]
    result = subprocess.run(args, capture_output=True, text=True, cwd=REPO_ROOT)
    return json.loads(result.stdout)


# ---- ROB-DRIFT-002 (ignore_changes wildcard + tags) ---------------------

def test_drift_002_fires_on_wildcard_form() -> None:
    out = _run("ignore_changes_wildcard", "--only-fixture", "ignore_changes_wildcard")
    findings = [f for f in out["findings"] if f["id"] == "ROB-DRIFT-002"]
    # Two patterns in the rule: ["*"] form and [tags] form.
    assert len(findings) == 2


def test_drift_002_does_not_fire_on_per_key_tag_form() -> None:
    """tags["LastModifiedBy"] suppresses one key — not the whole tags map."""
    out = _run("ROB-DRIFT-002_clean")
    assert "ROB-DRIFT-002" not in {f["id"] for f in out["findings"]}


# ---- ROB-FOREACH-002 (for_each keyset stability) ------------------------

def test_foreach_002_fires_on_splat_keyset() -> None:
    out = _run("foreach_keyset_unstable", "--only-fixture", "foreach_keyset_unstable")
    findings = [f for f in out["findings"] if f["id"] == "ROB-FOREACH-002"]
    addresses = {f["resource"] for f in findings}
    assert "aws_route_table_association.rta" in addresses


def test_foreach_002_fires_on_comprehension_keyset() -> None:
    out = _run("foreach_keyset_unstable", "--only-fixture", "foreach_keyset_unstable")
    addresses = {f["resource"] for f in out["findings"] if f["id"] == "ROB-FOREACH-002"}
    assert "aws_iam_role_policy_attachment.att" in addresses


def test_foreach_002_does_not_fire_on_input_driven_keyset() -> None:
    """var.X / local.X-driven for_each is stable — must NOT fire."""
    out = _run("ROB-FOREACH-002_clean")
    assert "ROB-FOREACH-002" not in {f["id"] for f in out["findings"]}


def test_foreach_002_emits_context_naming_the_unstable_source() -> None:
    out = _run("foreach_keyset_unstable", "--only-fixture", "foreach_keyset_unstable")
    findings = [f for f in out["findings"] if f["id"] == "ROB-FOREACH-002"]
    assert all("aws_subnet.*" in f.get("context", "") for f in findings)


# ---- MOD-UNUSED-001 (orphan module detector) ----------------------------

def test_mod_unused_001_fires_on_orphan_module() -> None:
    out = _run("module_orphaned", "--only-fixture", "module_orphaned")
    findings = [f for f in out["findings"] if f["id"] == "MOD-UNUSED-001"]
    assert len(findings) == 1
    assert findings[0]["resource"] == "<module:orphan>"


def test_mod_unused_001_does_not_fire_on_referenced_module() -> None:
    out = _run("module_orphaned", "--only-fixture", "module_orphaned")
    findings = [f for f in out["findings"] if f["id"] == "MOD-UNUSED-001"]
    addresses = {f["resource"] for f in findings}
    # `<module:used>` is referenced by scenarios/dev — must NOT appear.
    assert "<module:used>" not in addresses


def test_mod_unused_001_clean_fixture_no_orphans() -> None:
    out = _run("MOD-UNUSED-001_clean")
    assert "MOD-UNUSED-001" not in {f["id"] for f in out["findings"]}


# ---- applies_when adoption ---------------------------------------------

def test_applies_when_gates_rule_when_provider_too_old(tmp_path: Path) -> None:
    """An azurerm 2.x repo must NOT see SEC-AZURE-AKS-001 (gated to 3.0)."""
    (tmp_path / "main.tf").write_text(
        'terraform {\n'
        '  required_providers {\n'
        '    azurerm = { source = "hashicorp/azurerm", version = "~> 2.99" }\n'
        '  }\n'
        '}\n'
        'resource "azurerm_kubernetes_cluster" "old" {\n'
        '  name                              = "old-aks"\n'
        '  role_based_access_control_enabled = false\n'
        '}\n'
    )
    out = _run(tmp_path)
    assert "SEC-AZURE-AKS-001" not in {f["id"] for f in out["findings"]}


def test_applies_when_permits_rule_when_provider_meets_minimum(tmp_path: Path) -> None:
    """The same fixture with azurerm 3.x or no constraint must fire the rule."""
    (tmp_path / "main.tf").write_text(
        'terraform {\n'
        '  required_providers {\n'
        '    azurerm = { source = "hashicorp/azurerm", version = "~> 3.50" }\n'
        '  }\n'
        '}\n'
        'resource "azurerm_kubernetes_cluster" "modern" {\n'
        '  name                              = "modern-aks"\n'
        '  role_based_access_control_enabled = false\n'
        '}\n'
    )
    out = _run(tmp_path)
    assert "SEC-AZURE-AKS-001" in {f["id"] for f in out["findings"]}


def test_provider_constraint_allows_truth_table() -> None:
    """Lock every docstring example for `_provider_constraint_allows`
    plus the regression case that surfaced during the A1 sweep
    (`~> 3.50` was wrongly returning False against `min_v = 3.0`)."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from detect import _provider_constraint_allows  # type: ignore

    cases = [
        # docstring contract
        ("~> 5.40",          "5.0",   True),
        ("~> 4.50",          "5.0",   False),
        (">= 4.0",           "5.0",   True),
        ("< 5.0",            "5.0",   False),
        (">= 1.5.0, < 1.10", "1.10",  False),
        (">= 1.5.0",         "1.10",  True),
        ("",                 "5.0",   True),
        # regression: ~> with the lower bound above min_v
        ("~> 3.50",          "3.0",   True),
        ("~> 3.50",          "3.40",  True),
        ("~> 3.50",          "4.0",   False),
    ]
    for constraint, min_version, expected in cases:
        assert _provider_constraint_allows(constraint, min_version) is expected, (
            f"({constraint!r}, {min_version!r}) -> "
            f"{_provider_constraint_allows(constraint, min_version)}, expected {expected}"
        )


def test_applies_when_adoption_count() -> None:
    """Lock the adoption sweep so a regression (someone removes applies_when
    from a gated rule) is caught locally instead of only at runtime against
    the affected provider version."""
    catalog_dir = REPO_ROOT / "catalog"
    adopted = [
        p for p in catalog_dir.glob("*.yaml")
        if "applies_when:" in p.read_text()
    ]
    assert len(adopted) >= 8, (
        f"applies_when adoption regressed from 8 to {len(adopted)} rules. "
        f"This is a feature with a known dormancy problem; the test pins it."
    )
