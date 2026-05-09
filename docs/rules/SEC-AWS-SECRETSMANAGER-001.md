---
title: "SEC-AWS-SECRETSMANAGER-001 — Secrets Manager secret uses AWS-managed key (no CMK)"
description: "tf-analyze rule SEC-AWS-SECRETSMANAGER-001 (MEDIUM · security): Secrets Manager secret uses AWS-managed key (no CMK)"
keywords: "security, medium, terraform, iac, aws, cis-{'id': '3.8', 'title': 'Ensure rotation for customer created symmetric CMKs is enabled'}"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-SECRETSMANAGER-001 \u2014 Secrets Manager secret uses AWS-managed key (no CMK)",
  "description": "Specify a customer-managed KMS key:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-SECRETSMANAGER-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-SECRETSMANAGER-001/"
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
  "keywords": "security, medium, terraform, CIS {'id': '3.8', 'title': 'Ensure rotation for customer created symmetric CMKs is enabled'}",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AWS-SECRETSMANAGER-001 — Secrets Manager secret uses AWS-managed key (no CMK)

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-SECRETSMANAGER-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Secrets Manager secret uses AWS-managed key (no CMK).** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_secretsmanager_secret` (`kms_key_id`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_secretsmanager_secret` has no `kms_key_id`. The AWS-managed key
cannot be disabled, rotated on demand, or scoped to a specific IAM
principal. A customer-managed KMS key enables key policy enforcement
and CloudTrail audit of every secret decryption.

## Why it likely fired

`aws_secretsmanager_secret` has no `kms_key_id`. The AWS-managed key
cannot be disabled, rotated on demand, or scoped to a specific IAM
principal. A customer-managed KMS key enables key policy enforcement
and CloudTrail audit of every secret decryption.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-SECRETSMANAGER-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Specify a customer-managed KMS key:

    resource "aws_secretsmanager_secret" "app_db" {
      name       = "app/db/password"
      kms_key_id = aws_kms_key.secrets.arn
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_secretsmanager_secret" "example" {
  name       = "example"
  kms_key_id = aws_kms_key.secrets.arn
}
```

## Verification

```sh
`aws secretsmanager describe-secret --secret-id <name> --query 'KmsKeyId'`
must return your CMK ARN, not null or aws/secretsmanager.
```

## References

**CIS Benchmark**
  - `CIS 3.8` — Ensure rotation for customer created symmetric CMKs is enabled

**PCI-DSS**
  - `Req-3.6`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**Source**
  - [`catalog/SEC-AWS-SECRETSMANAGER-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-SECRETSMANAGER-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-SECRETSMANAGER-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-SECRETSMANAGER-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-SECRETSMANAGER-001
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
