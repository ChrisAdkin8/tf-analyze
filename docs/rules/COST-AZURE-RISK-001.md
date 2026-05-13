---
title: "COST-AZURE-RISK-001 — Azure resource missing cost control"
description: "tf-analyze rule COST-AZURE-RISK-001 (MEDIUM · ops): Azure resource missing cost control"
keywords: "ops, medium, terraform, iac, azure, mitre-T1496"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "COST-AZURE-RISK-001 \u2014 Azure resource missing cost control",
  "description": "Add explicit cost controls so a misconfigured workload cannot run up\nthe bill:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/COST-AZURE-RISK-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/COST-AZURE-RISK-001/"
  },
  "author": {
    "@type": "Organization",
    "name": "tf-analyze"
  },
  "publisher": {
    "@type": "Organization",
    "name": "tf-analyze",
    "url": "https://chrisadkin8.github.io/tf-analyze"
  },
  "keywords": "ops, medium, terraform, MITRE T1496",
  "proficiencyLevel": "Expert",
  "articleSection": "ops",
  "isAccessibleForFree": true
}
</script>

# 💡 COST-AZURE-RISK-001 — Azure resource missing cost control

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: ops](https://img.shields.io/badge/section-ops-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/COST-AZURE-RISK-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=COST-AZURE-RISK-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add COST-AZURE-RISK-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure resource missing cost control.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_kubernetes_cluster` (`sku_tier`) matching `/^Premium$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  AKS cluster on Premium tier — confirm uptime SLA is required (Premium ≈ 3x Standard cost)
2. **`resource_missing_arg`** on `azurerm_kubernetes_cluster_node_pool` (`enable_auto_scaling`) — _the resource is missing a required attribute (or nested attribute path)._
  Node pool without enable_auto_scaling (fixed node count, no scale-down on low utilisation)
3. **`resource_missing_arg`** on `azurerm_cosmosdb_account` (`capabilities`) — _the resource is missing a required attribute (or nested attribute path)._
  Cosmos account without `capabilities { name = "EnableServerless" }` and
no explicit provisioned `throughput` block on associated containers.
Provisioned throughput defaults are expensive ($24/mo per 100 RU/s).
4. **`resource_missing_arg`** on `azurerm_mssql_database` (`max_size_gb`) — _the resource is missing a required attribute (or nested attribute path)._
  SQL Database without max_size_gb (unbounded growth → unbounded billing)
5. **`resource_missing_arg`** on `azurerm_log_analytics_workspace` (`daily_quota_gb`) — _the resource is missing a required attribute (or nested attribute path)._
  Log Analytics workspace without daily_quota_gb (uncapped ingestion cost on a misbehaving agent)

## Why it likely fired

AKS cluster on Premium tier — confirm uptime SLA is required (Premium ≈ 3x Standard cost)

Node pool without enable_auto_scaling (fixed node count, no scale-down on low utilisation)

Cosmos account without `capabilities { name = "EnableServerless" }` and
no explicit provisioned `throughput` block on associated containers.
Provisioned throughput defaults are expensive ($24/mo per 100 RU/s).

SQL Database without max_size_gb (unbounded growth → unbounded billing)

Log Analytics workspace without daily_quota_gb (uncapped ingestion cost on a misbehaving agent)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain COST-AZURE-RISK-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add explicit cost controls so a misconfigured workload cannot run up
the bill:

- AKS: justify Premium tier (24x7 SLA), enable auto-scaling on
  node pools so idle hours scale down.
- Cosmos DB: prefer `capabilities { name = "EnableServerless" }` for
  spiky workloads; pin `throughput` on provisioned containers.
- Azure SQL: set `max_size_gb` to bound disk growth.
- Log Analytics: set `daily_quota_gb` to cap ingestion when a runaway
  agent or noisy diagnostic pipe floods the workspace.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_kubernetes_cluster_node_pool" "main" {
  name                  = "default"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id
  vm_size               = "Standard_D2s_v3"
  enable_auto_scaling   = true
  min_count             = 1
  max_count             = 5
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-main"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  daily_quota_gb      = 10
}
```

## Verification

Review the next `terraform plan` to confirm each named arg is now set,
and configure Cost Management budgets on the subscription:
`az consumption budget create --budget-name <name> --amount <usd> ...`

## References

**MITRE ATT&CK**
  - [`T1496`](https://attack.mitre.org/techniques/T1496/)

**Source**
  - [`catalog/COST-AZURE-RISK-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/COST-AZURE-RISK-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain COST-AZURE-RISK-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore COST-AZURE-RISK-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - COST-AZURE-RISK-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
{% if site.giscus.enabled %}
---

## Discussion

<script src="https://giscus.app/client.js"
        data-repo="{{ site.giscus.repo }}"
        data-repo-id="{{ site.giscus.repo_id }}"
        data-category="{{ site.giscus.category }}"
        data-category-id="{{ site.giscus.category_id }}"
        data-mapping="{{ site.giscus.mapping }}"
        data-strict="0"
        data-reactions-enabled="{{ site.giscus.reactions }}"
        data-emit-metadata="{{ site.giscus.emit_metadata }}"
        data-input-position="{{ site.giscus.input_position }}"
        data-theme="{{ site.giscus.theme }}"
        data-lang="en"
        crossorigin="anonymous"
        async>
</script>

{% endif %}
