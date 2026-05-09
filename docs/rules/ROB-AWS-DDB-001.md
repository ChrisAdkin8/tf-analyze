---
title: "ROB-AWS-DDB-001 — DynamoDB table missing deletion protection"
description: "tf-analyze rule ROB-AWS-DDB-001 (HIGH · robustness): DynamoDB table missing deletion protection"
keywords: "robustness, high, terraform, iac, aws"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-AWS-DDB-001 \u2014 DynamoDB table missing deletion protection",
  "description": "Set `deletion_protection_enabled = true` on every production table:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-DDB-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-DDB-001/"
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
  "keywords": "robustness, high, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# ⚠️ ROB-AWS-DDB-001 — DynamoDB table missing deletion protection

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-AWS-DDB-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-AWS-DDB-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-AWS-DDB-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **DynamoDB table missing deletion protection.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_dynamodb_table` (`deletion_protection_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_dynamodb_table` without `deletion_protection_enabled`. The
default is `false`, so a `terraform destroy` or accidental module
removal permanently deletes the table and all its items.
2. **`hcl_attr`** on `aws_dynamodb_table` (`deletion_protection_enabled`) not equal to `True` — _an attribute value differs from the expected literal._
  `deletion_protection_enabled = false` explicitly removes the guard
against accidental table deletion.

## Why it likely fired

`aws_dynamodb_table` without `deletion_protection_enabled`. The
default is `false`, so a `terraform destroy` or accidental module
removal permanently deletes the table and all its items.

`deletion_protection_enabled = false` explicitly removes the guard
against accidental table deletion.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-DDB-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `deletion_protection_enabled = true` on every production table:

    resource "aws_dynamodb_table" "app" {
      name                        = "app"
      billing_mode                = "PAY_PER_REQUEST"
      hash_key                    = "id"
      deletion_protection_enabled = true

      attribute {
        name = "id"
        type = "S"
      }
    }

Pair with `lifecycle { prevent_destroy = true }` for a two-layer guard.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_dynamodb_table" "example" {
  name                        = "example"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "id"
  deletion_protection_enabled = true

  attribute {
    name = "id"
    type = "S"
  }
}
```

## Verification

```sh
`aws dynamodb describe-table --table-name <name> \
  --query 'Table.DeletionProtectionEnabled'`
must return `true`.
```

## References

**SOC 2 Trust Services Criteria**
  - `A1.2`

**Source**
  - [`catalog/ROB-AWS-DDB-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-DDB-001.yaml) — canonical YAML

## Family

See also rules in the `ROB-AWS-DDB-*` family:

- [`ROB-AWS-DDB-002`](./ROB-AWS-DDB-002.md) — DynamoDB table missing point-in-time recovery

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-DDB-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-DDB-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-DDB-001
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
