# 💡 SEC-AZURE-MI-001 — Azure user-assigned identity with no role assignment (orphan UAMI)

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Azure user-assigned identity with no role assignment (orphan UAMI).** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`graph_check`** — _a corpus-wide graph check fired (cross-resource invariant)._
  An `azurerm_user_assigned_identity` resource is defined but no
`azurerm_role_assignment` references its `principal_id`. The identity
is an orphan — it was likely created for a workload that was removed
or never wired up. Orphan identities accumulate over time and widen
the blast radius of a credential compromise because an attacker who
gains their token can enumerate entitlements that engineers have
forgotten are still live.

## Why it likely fired

An `azurerm_user_assigned_identity` resource is defined but no
`azurerm_role_assignment` references its `principal_id`. The identity
is an orphan — it was likely created for a workload that was removed
or never wired up. Orphan identities accumulate over time and widen
the blast radius of a credential compromise because an attacker who
gains their token can enumerate entitlements that engineers have
forgotten are still live.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-MI-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Either attach the identity to a role assignment with minimum-privilege
scope, or delete it if it is no longer needed:

    # Option A — wire to a scoped role assignment
    resource "azurerm_role_assignment" "app" {
      scope                = azurerm_resource_group.app.id
      role_definition_name = "Storage Blob Data Reader"
      principal_id         = azurerm_user_assigned_identity.app.principal_id
    }

    # Option B — remove the orphan identity entirely
    # (delete the azurerm_user_assigned_identity block)

Audit existing role assignments with:
`az role assignment list --assignee <principal-id> -o table`

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_role_assignment" "example" {
  scope                = azurerm_storage_account.example.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.example.principal_id
}
```

## Verification

```sh
`az identity list --resource-group <rg> --query '[].{Name:name,PrincipalId:principalId}' -o table`
then for each principal ID:
`az role assignment list --assignee <principal-id> -o table`
must return at least one row.
```

## References

**Source**
  - [`catalog/SEC-AZURE-MI-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-MI-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-MI-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-MI-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-MI-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
