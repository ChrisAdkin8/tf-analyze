---
title: "COST-AWS-RISK-001 — AWS resource missing cost control"
description: "tf-analyze rule COST-AWS-RISK-001 (MEDIUM · ops): AWS resource missing cost control"
keywords: "ops, medium, terraform, iac, aws"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "COST-AWS-RISK-001 \u2014 AWS resource missing cost control",
  "description": "Add explicit cost controls:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/COST-AWS-RISK-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/COST-AWS-RISK-001/"
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
  "keywords": "ops, medium, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "ops",
  "isAccessibleForFree": true
}
</script>

# 💡 COST-AWS-RISK-001 — AWS resource missing cost control

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: ops](https://img.shields.io/badge/section-ops-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/COST-AWS-RISK-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=COST-AWS-RISK-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add COST-AWS-RISK-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **AWS resource missing cost control.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_cloudwatch_log_group` (`retention_in_days`) — _the resource is missing a required attribute (or nested attribute path)._
  CloudWatch log group without `retention_in_days`. Logs are retained
indefinitely by default — CloudWatch storage is billed per GB/month
and log groups without retention are a routine source of cost drift
in large accounts.
2. **`resource_missing_arg`** on `aws_autoscaling_group` (`max_size`) — _the resource is missing a required attribute (or nested attribute path)._
  Auto Scaling Group without explicit `max_size`. Without a cap,
a runaway scale-out event can generate thousands of instances and
tens of thousands of dollars before anyone notices.

## Why it likely fired

CloudWatch log group without `retention_in_days`. Logs are retained
indefinitely by default — CloudWatch storage is billed per GB/month
and log groups without retention are a routine source of cost drift
in large accounts.

Auto Scaling Group without explicit `max_size`. Without a cap,
a runaway scale-out event can generate thousands of instances and
tens of thousands of dollars before anyone notices.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain COST-AWS-RISK-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add explicit cost controls:

    # CloudWatch log group — expire logs after 90 days (adjust per retention policy)
    resource "aws_cloudwatch_log_group" "app" {
      name              = "/app/logs"
      retention_in_days = 90
    }

    # ASG — always set an explicit max_size
    resource "aws_autoscaling_group" "app" {
      min_size = 1
      max_size = 10   # explicit upper bound
      # ...
    }

Pair with AWS Budgets alerts so cost anomalies page on-call before
the bill arrives.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_cloudwatch_log_group" "app" {
  name              = "/app/logs"
  retention_in_days = 90
}

resource "aws_autoscaling_group" "app" {
  min_size         = 1
  max_size         = 10
  desired_capacity = 2
}
```

## Verification

For log groups: `aws logs describe-log-groups --log-group-name-prefix /app \
  --query 'logGroups[?retentionInDays==null].logGroupName'`
must return empty.
For ASGs: confirm `max_size` is set and reasonable in `terraform show`.

## References

**Source**
  - [`catalog/COST-AWS-RISK-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/COST-AWS-RISK-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain COST-AWS-RISK-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore COST-AWS-RISK-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - COST-AWS-RISK-001
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
