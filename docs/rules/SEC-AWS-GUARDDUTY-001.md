---
title: "SEC-AWS-GUARDDUTY-001 — GuardDuty detector not provisioned"
description: "tf-analyze rule SEC-AWS-GUARDDUTY-001 (HIGH · security): GuardDuty detector not provisioned"
keywords: "security, high, terraform, iac, aws, cis-{'id': '3.3', 'title': 'Ensure AWS Config is enabled in all regions'}, mitre-T1562.001"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-GUARDDUTY-001 \u2014 GuardDuty detector not provisioned",
  "description": "Enable GuardDuty in every account and region:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-GUARDDUTY-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-GUARDDUTY-001/"
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
  "keywords": "security, high, terraform, CIS {'id': '3.3', 'title': 'Ensure AWS Config is enabled in all regions'}, MITRE T1562.001",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-GUARDDUTY-001 — GuardDuty detector not provisioned

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-GUARDDUTY-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-GUARDDUTY-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-GUARDDUTY-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GuardDuty detector not provisioned.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_absent`** on `aws_guardduty_detector` — _the corpus is missing a resource type we expected to find given other resources present._
  No `aws_guardduty_detector` is provisioned. GuardDuty uses machine-learning
and threat intelligence to detect account compromise, instance compromise,
and data exfiltration in real time. Without it, there is no continuous
monitoring of CloudTrail, VPC Flow Logs, and DNS logs for malicious activity.
GuardDuty is a prerequisite for Security Hub aggregation and many compliance
frameworks.

## Why it likely fired

No `aws_guardduty_detector` is provisioned. GuardDuty uses machine-learning
and threat intelligence to detect account compromise, instance compromise,
and data exfiltration in real time. Without it, there is no continuous
monitoring of CloudTrail, VPC Flow Logs, and DNS logs for malicious activity.
GuardDuty is a prerequisite for Security Hub aggregation and many compliance
frameworks.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-GUARDDUTY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable GuardDuty in every account and region:

    resource "aws_guardduty_detector" "main" {
      enable = true

      datasources {
        s3_logs { enable = true }
        kubernetes { audit_logs { enable = true } }
        malware_protection {
          scan_ec2_instance_with_findings { ebs_volumes { enable = true } }
        }
      }
    }

Use `aws_guardduty_organization_admin_account` to enable GuardDuty
org-wide from the management account.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_guardduty_detector" "main" {
  enable = true
}
```

## Verification

```sh
`aws guardduty list-detectors --query 'DetectorIds'`
must return at least one detector ID.
```

## References

**CIS Benchmark**
  - `CIS 3.3` — Ensure AWS Config is enabled in all regions

**PCI-DSS**
  - `Req-10.6`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1562.001`](https://attack.mitre.org/techniques/T1562/001/)

**Source**
  - [`catalog/SEC-AWS-GUARDDUTY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-GUARDDUTY-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-GUARDDUTY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-GUARDDUTY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-GUARDDUTY-001
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
