---
title: "SEC-AWS-WAF-002 — ALB/CloudFront/API-Gateway has WAF associated but no rate-based rule"
description: "tf-analyze rule SEC-AWS-WAF-002 (MEDIUM · security): ALB/CloudFront/API-Gateway has WAF associated but no rate-based rule"
keywords: "security, medium, terraform, iac, aws, mitre-T1499.002, cwe-770"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-WAF-002 \u2014 ALB/CloudFront/API-Gateway has WAF associated but no rate-based rule",
  "description": "resource \"aws_wafv2_web_acl\" \"edge\" {\n  # \u2026 existing managed rule groups \u2026",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-WAF-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-WAF-002/"
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
  "keywords": "security, medium, terraform, MITRE T1499.002, CWE-770",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AWS-WAF-002 — ALB/CloudFront/API-Gateway has WAF associated but no rate-based rule

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-WAF-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-WAF-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-WAF-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **ALB/CloudFront/API-Gateway has WAF associated but no rate-based rule.** This rule has `default_urgency: MEDIUM` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_wafv2_web_acl` (`rule.statement.rate_based_statement`) — _the resource is missing a required attribute (or nested attribute path)._
  A WAFv2 web ACL without any `rate_based_statement` rule has no
automatic flood protection. ManagedRuleGroupStatement entries
(e.g. AWSManagedRulesCommonRuleSet) catch known patterns but
don't gate raw request rate. OWASP API4 (Unrestricted Resource
Consumption) explicitly calls out rate-based blocking as the
mitigation for credential-stuffing and API scraping.

## Why it likely fired

A WAFv2 web ACL without any `rate_based_statement` rule has no
automatic flood protection. ManagedRuleGroupStatement entries
(e.g. AWSManagedRulesCommonRuleSet) catch known patterns but
don't gate raw request rate. OWASP API4 (Unrestricted Resource
Consumption) explicitly calls out rate-based blocking as the
mitigation for credential-stuffing and API scraping.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-WAF-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

resource "aws_wafv2_web_acl" "edge" {
  # … existing managed rule groups …

  rule {
    name     = "rate-block-2k-rpm"
    priority = 99
    action { block {} }
    statement {
      rate_based_statement {
        limit              = 2000  # per 5 min, per IP
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-block-2k-rpm"
      sampled_requests_enabled   = true
    }
  }
}

## Verification

```sh
`aws wafv2 get-web-acl --scope REGIONAL --id <id>` should include
at least one Statement with a RateBasedStatement entry.
```

## References

**MITRE ATT&CK**
  - [`T1499.002`](https://attack.mitre.org/techniques/T1499/002/)

**CWE**
  - [`CWE-770`](https://cwe.mitre.org/data/definitions/770.html)

**Source**
  - [`catalog/SEC-AWS-WAF-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-WAF-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-AWS-WAF-*` family:

- [`SEC-AWS-WAF-001`](./SEC-AWS-WAF-001.md) — WAFv2 web ACL missing logging configuration

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-WAF-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-WAF-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-WAF-002
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
