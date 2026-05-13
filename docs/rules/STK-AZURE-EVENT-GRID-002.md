---
title: "STK-AZURE-EVENT-GRID-002 — Azure Event Grid event subscription missing dead-letter destination"
description: "tf-analyze rule STK-AZURE-EVENT-GRID-002 (MEDIUM · stack): Azure Event Grid event subscription missing dead-letter destination"
keywords: "stack, medium, terraform, iac, azure, mitre-T1499.002, cwe-770, nist-csf-pr.pt-4, nist-800-53-sc-5"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-EVENT-GRID-002 \u2014 Azure Event Grid event subscription missing dead-letter destination",
  "description": "Configure a dead-letter destination pointing at a storage blob:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-EVENT-GRID-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-EVENT-GRID-002/"
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
  "keywords": "stack, medium, terraform, MITRE T1499.002, CWE-770",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-AZURE-EVENT-GRID-002 — Azure Event Grid event subscription missing dead-letter destination

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-EVENT-GRID-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-EVENT-GRID-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-EVENT-GRID-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Event Grid event subscription missing dead-letter destination.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_eventgrid_event_subscription` (`dead_letter_identity`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_eventgrid_event_subscription` has neither
`dead_letter_identity` nor `storage_blob_dead_letter_destination`.
Events that fail to deliver after the retry policy expires are
silently dropped — incident response cannot reconstruct missed
messages. Equivalent to AWS Lambda DLQ gap.

## Why it likely fired

`azurerm_eventgrid_event_subscription` has neither
`dead_letter_identity` nor `storage_blob_dead_letter_destination`.
Events that fail to deliver after the retry policy expires are
silently dropped — incident response cannot reconstruct missed
messages. Equivalent to AWS Lambda DLQ gap.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-EVENT-GRID-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Configure a dead-letter destination pointing at a storage blob:

    resource "azurerm_eventgrid_event_subscription" "main" {
      # ...
      storage_blob_dead_letter_destination {
        storage_account_id          = azurerm_storage_account.dlq.id
        storage_blob_container_name = azurerm_storage_container.dlq.name
      }
      retry_policy {
        max_delivery_attempts = 30
        event_time_to_live    = 1440
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_eventgrid_event_subscription" "example" {
  name  = "example"
  scope = azurerm_eventgrid_topic.example.id
  webhook_endpoint {
    url = "https://example.com/webhook"
  }
  storage_blob_dead_letter_destination {
    storage_account_id          = azurerm_storage_account.dlq.id
    storage_blob_container_name = "dlq"
  }
  retry_policy {
    max_delivery_attempts = 30
    event_time_to_live    = 1440
  }
}
```

## Verification

```sh
`az eventgrid event-subscription show --name <name> --source-resource-id <id>` must
show a populated `deadLetterDestination`.
```

## References

**MITRE ATT&CK**
  - [`T1499.002`](https://attack.mitre.org/techniques/T1499/002/)

**CWE**
  - [`CWE-770`](https://cwe.mitre.org/data/definitions/770.html)

**NIST CSF 2.0**
  - [`PR.PT-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-5)

**Source**
  - [`catalog/STK-AZURE-EVENT-GRID-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-EVENT-GRID-002.yaml) — canonical YAML

## Family

See also rules in the `STK-AZURE-EVENT-GRID-*` family:

- [`STK-AZURE-EVENT-GRID-001`](./STK-AZURE-EVENT-GRID-001.md) — Azure Event Grid topic missing managed identity and CMK

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-EVENT-GRID-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-EVENT-GRID-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-EVENT-GRID-002
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
