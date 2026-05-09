---
title: "ROB-AWS-SECRETSMANAGER-001 — Secrets Manager secret has no automatic rotation configured"
description: "tf-analyze rule ROB-AWS-SECRETSMANAGER-001 (MEDIUM · robustness): Secrets Manager secret has no automatic rotation configured"
keywords: "robustness, medium, terraform, iac, aws"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-AWS-SECRETSMANAGER-001 \u2014 Secrets Manager secret has no automatic rotation configured",
  "description": "Define a rotation configuration for every secret that supports it:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-SECRETSMANAGER-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-SECRETSMANAGER-001/"
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
  "keywords": "robustness, medium, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# 💡 ROB-AWS-SECRETSMANAGER-001 — Secrets Manager secret has no automatic rotation configured

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-AWS-SECRETSMANAGER-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-AWS-SECRETSMANAGER-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-AWS-SECRETSMANAGER-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Secrets Manager secret has no automatic rotation configured.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_absent`** on `aws_secretsmanager_secret_rotation` — _the corpus is missing a resource type we expected to find given other resources present._
  An `aws_secretsmanager_secret` exists but no `aws_secretsmanager_secret_rotation`
resource is defined. Without automatic rotation, long-lived credentials accumulate
blast radius over time. A leaked credential that is never rotated provides
indefinite access.

## Why it likely fired

An `aws_secretsmanager_secret` exists but no `aws_secretsmanager_secret_rotation`
resource is defined. Without automatic rotation, long-lived credentials accumulate
blast radius over time. A leaked credential that is never rotated provides
indefinite access.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-SECRETSMANAGER-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Define a rotation configuration for every secret that supports it:

    resource "aws_secretsmanager_secret_rotation" "db" {
      secret_id           = aws_secretsmanager_secret.db.id
      rotation_lambda_arn = aws_lambda_function.rotate_secret.arn

      rotation_rules {
        automatically_after_days = 30
      }
    }

Use AWS-provided rotation Lambdas for RDS, Redshift, and DocumentDB secrets.
For custom secrets, implement the standard rotation Lambda contract.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_secretsmanager_secret_rotation" "example" {
  secret_id           = aws_secretsmanager_secret.example.id
  rotation_lambda_arn = aws_lambda_function.rotate_secret.arn
  rotation_rules {
    automatically_after_days = 30
  }
}
```

## Verification

```sh
`aws secretsmanager describe-secret --secret-id <name> \
  --query 'RotationEnabled'`
must return `true`.
```

## References

**PCI-DSS**
  - `Req-8.6`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**Source**
  - [`catalog/ROB-AWS-SECRETSMANAGER-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-SECRETSMANAGER-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-SECRETSMANAGER-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-SECRETSMANAGER-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-SECRETSMANAGER-001
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
