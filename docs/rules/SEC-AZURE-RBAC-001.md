# ⚠️ SEC-AZURE-RBAC-001 — Azure role assignment scope is subscription-wide

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **Azure role assignment scope is subscription-wide.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_role_assignment` (`scope`) matching `/^data\.azurerm_subscription\.|^"?\/subscriptions\/[^/]+\/?"?$|management_group/` — _the resource declares the named attribute, but its value matches the rule's pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-RBAC-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace the subscription- or management-group-wide scope with the
narrowest resource-level scope that still satisfies the use case.
Examples:

    # Bad — applies the role to every resource in the subscription
    scope = data.azurerm_subscription.primary.id

    # Better — applies the role to a single resource group
    scope = azurerm_resource_group.app.id

    # Best — applies the role to a specific resource
    scope = azurerm_storage_account.app.id

If a subscription-wide scope is genuinely required (rare — usually
`Reader` for monitoring tooling), document the rationale in a comment
and switch to a built-in role with audit-only permissions.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_role_assignment" "example" {
  scope                = azurerm_resource_group.example.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.example.principal_id
}
```

## Verification

After applying, confirm with:

    az role assignment list --assignee <principal-id> --output table

The `Scope` column should show a resource-group or resource path,
not `/subscriptions/<sub-id>`.

## References

**CIS Benchmark**
  - `CIS 1.21`

**PCI-DSS**
  - `Req-7.1`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**Related rules**
  - [`SEC-IAM-001`](./SEC-IAM-001.md)

**Source**
  - [`catalog/SEC-AZURE-RBAC-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-RBAC-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-RBAC-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-RBAC-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-RBAC-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
