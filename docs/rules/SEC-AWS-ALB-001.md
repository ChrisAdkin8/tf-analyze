---
title: "SEC-AWS-ALB-001 — Load balancer access logs disabled"
description: "tf-analyze rule SEC-AWS-ALB-001 (MEDIUM · security): Load balancer access logs disabled"
keywords: "security, medium, terraform, iac, aws, cis-{'id': '2.6', 'title': "Ensure that S3 buckets are configured with 'Block public access'"}"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-ALB-001 \u2014 Load balancer access logs disabled",
  "description": "Enable access logs and point them at an S3 bucket with appropriate retention:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-ALB-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-ALB-001/"
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
  "keywords": "security, medium, terraform, CIS {'id': '2.6', 'title': \"Ensure that S3 buckets are configured with 'Block public access'\"}",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AWS-ALB-001 — Load balancer access logs disabled

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-ALB-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-ALB-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-ALB-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Load balancer access logs disabled.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_lb` (`access_logs`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_lb` has no `access_logs` block, or `access_logs.enabled` is absent/false.
Without access logs, there is no record of which clients reached the load
balancer, what paths they requested, or which backend targets served them.
Access logs are essential for incident response, DDoS attribution, and
compliance audits.
2. **`resource_missing_arg`** on `aws_alb` (`access_logs`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_alb` (legacy alias) has access logs disabled.

## Why it likely fired

`aws_lb` has no `access_logs` block, or `access_logs.enabled` is absent/false.
Without access logs, there is no record of which clients reached the load
balancer, what paths they requested, or which backend targets served them.
Access logs are essential for incident response, DDoS attribution, and
compliance audits.

`aws_alb` (legacy alias) has access logs disabled.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-ALB-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable access logs and point them at an S3 bucket with appropriate retention:

    resource "aws_lb" "main" {
      # ...
      access_logs {
        bucket  = aws_s3_bucket.alb_logs.id
        prefix  = "main-lb"
        enabled = true
      }
    }

The S3 bucket must have a bucket policy granting the ELB service account
`s3:PutObject` permission.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_lb" "example" {
  name               = "example"
  load_balancer_type = "application"
  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = "alb"
    enabled = true
  }
}
```

## Verification

```sh
`aws elbv2 describe-load-balancer-attributes \
  --load-balancer-arn <arn> \
  --query 'Attributes[?Key==\`access_logs.s3.enabled\`].Value'`
must return `"true"`.
```

## References

**CIS Benchmark**
  - `CIS 2.6` — Ensure that S3 buckets are configured with 'Block public access'

**PCI-DSS**
  - `Req-10.2`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**Source**
  - [`catalog/SEC-AWS-ALB-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-ALB-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-ALB-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-ALB-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-ALB-001
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
