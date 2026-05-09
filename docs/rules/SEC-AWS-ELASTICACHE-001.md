---
title: "SEC-AWS-ELASTICACHE-001 — ElastiCache replication group missing encryption"
description: "tf-analyze rule SEC-AWS-ELASTICACHE-001 (HIGH · security): ElastiCache replication group missing encryption"
keywords: "security, high, terraform, iac, aws"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-ELASTICACHE-001 \u2014 ElastiCache replication group missing encryption",
  "description": "Enable both at-rest and in-transit encryption:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-ELASTICACHE-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-ELASTICACHE-001/"
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
  "keywords": "security, high, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-ELASTICACHE-001 — ElastiCache replication group missing encryption

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-ELASTICACHE-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **ElastiCache replication group missing encryption.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_elasticache_replication_group` (`at_rest_encryption_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
2. **`hcl_attr`** on `aws_elasticache_replication_group` (`at_rest_encryption_enabled`) not equal to `True` — _an attribute value differs from the expected literal._
3. **`resource_missing_arg`** on `aws_elasticache_replication_group` (`transit_encryption_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
4. **`hcl_attr`** on `aws_elasticache_replication_group` (`transit_encryption_enabled`) not equal to `True` — _an attribute value differs from the expected literal._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-ELASTICACHE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable both at-rest and in-transit encryption:

    resource "aws_elasticache_replication_group" "app" {
      replication_group_id = "app"
      description          = "App cache"

      at_rest_encryption_enabled = true
      transit_encryption_enabled = true
      auth_token                 = var.redis_auth_token
    }

In-transit encryption (TLS) requires `auth_token` to be set as well.
Without both flags, cache traffic and data are visible to anyone with
network access to the cluster endpoint.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "aws_elasticache_replication_group" "example" {
  # ... other arguments ...
  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
  auth_token                  = var.auth_token
}
```

_Encryption settings cannot be changed on an existing ElastiCache cluster — requires replacement._

## Verification

```sh
`aws elasticache describe-replication-groups --replication-group-id <id> \
  --query 'ReplicationGroups[0].{AtRest:AtRestEncryptionEnabled,InTransit:TransitEncryptionEnabled}'`
both values must be `true`.
```

## References

**Source**
  - [`catalog/SEC-AWS-ELASTICACHE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-ELASTICACHE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-ELASTICACHE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-ELASTICACHE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-ELASTICACHE-001
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
