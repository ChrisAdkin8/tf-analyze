---
title: "SEC-AWS-SECURITYHUB-001 — Security Hub not enabled"
description: "tf-analyze rule SEC-AWS-SECURITYHUB-001 (MEDIUM · security): Security Hub not enabled"
keywords: "security, medium, terraform, iac, aws, mitre-T1562.001, cwe-693"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-SECURITYHUB-001 \u2014 Security Hub not enabled",
  "description": "Enable Security Hub and subscribe to relevant standards:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-SECURITYHUB-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-SECURITYHUB-001/"
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
  "keywords": "security, medium, terraform, MITRE T1562.001, CWE-693",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AWS-SECURITYHUB-001 — Security Hub not enabled

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-SECURITYHUB-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-SECURITYHUB-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-SECURITYHUB-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Security Hub not enabled.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`resource_absent`** on `aws_securityhub_account` — _the corpus is missing a resource type we expected to find given other resources present._
  No `aws_securityhub_account` resource is defined. Security Hub aggregates
findings from GuardDuty, Inspector, Macie, IAM Access Analyzer, and partner
integrations into a single prioritised view. Without it, security findings
are siloed across services and require manual correlation. Security Hub also
provides AWS Foundational Security Best Practices (FSBP) and CIS benchmark
automated checks.

## Why it likely fired

No `aws_securityhub_account` resource is defined. Security Hub aggregates
findings from GuardDuty, Inspector, Macie, IAM Access Analyzer, and partner
integrations into a single prioritised view. Without it, security findings
are siloed across services and require manual correlation. Security Hub also
provides AWS Foundational Security Best Practices (FSBP) and CIS benchmark
automated checks.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-SECURITYHUB-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable Security Hub and subscribe to relevant standards:

    resource "aws_securityhub_account" "main" {}

    resource "aws_securityhub_standards_subscription" "cis" {
      standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
      depends_on    = [aws_securityhub_account.main]
    }

    resource "aws_securityhub_standards_subscription" "fsbp" {
      standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
      depends_on    = [aws_securityhub_account.main]
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_securityhub_account" "main" {}
```

## Verification

```sh
`aws securityhub describe-hub --query 'HubArn'`
must return a Hub ARN (non-empty).
```

## References

**PCI-DSS**
  - `Req-10.6`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1562.001`](https://attack.mitre.org/techniques/T1562/001/)

**CWE**
  - [`CWE-693`](https://cwe.mitre.org/data/definitions/693.html)

**Source**
  - [`catalog/SEC-AWS-SECURITYHUB-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-SECURITYHUB-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-SECURITYHUB-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-SECURITYHUB-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-SECURITYHUB-001
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
