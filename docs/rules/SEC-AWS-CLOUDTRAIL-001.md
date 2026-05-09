---
title: "SEC-AWS-CLOUDTRAIL-001 — CloudTrail not enabled for all regions"
description: "tf-analyze rule SEC-AWS-CLOUDTRAIL-001 (CRITICAL · security): CloudTrail not enabled for all regions"
keywords: "security, critical, terraform, iac, aws, cis-3.1, mitre-T1562.008"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-CLOUDTRAIL-001 \u2014 CloudTrail not enabled for all regions",
  "description": "Set `is_multi_region_trail = true` and `include_global_service_events = true`\non every `aws_cloudtrail`. Single-region trails miss API calls made in\nregions that are not currently in active use. Attackers deliberately use\nquiet or seldom-mo",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-CLOUDTRAIL-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-CLOUDTRAIL-001/"
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
  "keywords": "security, critical, terraform, CIS 3.1, MITRE T1562.008",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-AWS-CLOUDTRAIL-001 — CloudTrail not enabled for all regions

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-CLOUDTRAIL-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-CLOUDTRAIL-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-CLOUDTRAIL-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **CloudTrail not enabled for all regions.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`resource_arg`** on `aws_cloudtrail` (`is_multi_region_trail`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  CloudTrail with is_multi_region_trail = false
2. **`resource_missing_arg`** on `aws_cloudtrail` (`is_multi_region_trail`) — _the resource is missing a required attribute (or nested attribute path)._
  CloudTrail missing is_multi_region_trail (defaults to false)

## Why it likely fired

CloudTrail with is_multi_region_trail = false

CloudTrail missing is_multi_region_trail (defaults to false)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-CLOUDTRAIL-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `is_multi_region_trail = true` and `include_global_service_events = true`
on every `aws_cloudtrail`. Single-region trails miss API calls made in
regions that are not currently in active use. Attackers deliberately use
quiet or seldom-monitored regions to create IAM users, launch instances,
or establish persistence. A multi-region trail ensures all management
events — including those for global services like IAM and STS — flow to
a single, monitored log destination (CIS AWS 2.1, 2.4).

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_cloudtrail" "example" {
  # ... other arguments ...
  is_multi_region_trail = true
  include_global_service_events = true
}
```

## Verification

Run `aws cloudtrail describe-trails --trail-name-list <name>` and
confirm `IsMultiRegionTrail` is `true`. Run `terraform plan` and verify
no diff shows `is_multi_region_trail = false` or a missing value.

## References

**CIS Benchmark**
  - `CIS 3.1`

**PCI-DSS**
  - `Req-10.2`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1562.008`](https://attack.mitre.org/techniques/T1562/008/)

**Source**
  - [`catalog/SEC-AWS-CLOUDTRAIL-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-CLOUDTRAIL-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-AWS-CLOUDTRAIL-*` family:

- [`SEC-AWS-CLOUDTRAIL-002`](./SEC-AWS-CLOUDTRAIL-002.md) — CloudTrail log file integrity validation disabled

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-CLOUDTRAIL-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-CLOUDTRAIL-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-CLOUDTRAIL-001
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
