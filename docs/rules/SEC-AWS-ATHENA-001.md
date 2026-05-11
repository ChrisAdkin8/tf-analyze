---
title: "SEC-AWS-ATHENA-001 — Athena workgroup results not encrypted"
description: "tf-analyze rule SEC-AWS-ATHENA-001 (MEDIUM · security): Athena workgroup results not encrypted"
keywords: "security, medium, terraform, iac, aws, nist-csf-pr.ds-1, nist-800-53-sc-13, nist-800-53-sc-28, csa-ccm-cek-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-ATHENA-001 \u2014 Athena workgroup results not encrypted",
  "description": "Enforce SSE-KMS encryption at the workgroup level:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-ATHENA-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-ATHENA-001/"
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
  "keywords": "security, medium, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AWS-ATHENA-001 — Athena workgroup results not encrypted

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-ATHENA-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-ATHENA-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-ATHENA-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Athena workgroup results not encrypted.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_athena_workgroup` (`encryption_option`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_athena_workgroup` has no `encryption_configuration` in its
`result_configuration` block. Query results written to S3 use
SSE-S3 by default but this can be overridden by individual users.
Locking encryption at the workgroup level with SSE-KMS ensures
results are always encrypted with a customer-controlled key and
the setting cannot be bypassed.

## Why it likely fired

`aws_athena_workgroup` has no `encryption_configuration` in its
`result_configuration` block. Query results written to S3 use
SSE-S3 by default but this can be overridden by individual users.
Locking encryption at the workgroup level with SSE-KMS ensures
results are always encrypted with a customer-controlled key and
the setting cannot be bypassed.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-ATHENA-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enforce SSE-KMS encryption at the workgroup level:

    resource "aws_athena_workgroup" "main" {
      name = "main"
      configuration {
        enforce_workgroup_configuration = true
        result_configuration {
          output_location = "s3://${aws_s3_bucket.results.bucket}/output/"
          encryption_configuration {
            encryption_option = "SSE_KMS"
            kms_key_arn       = aws_kms_key.athena.arn
          }
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_athena_workgroup" "example" {
  name = "example"
  configuration {
    enforce_workgroup_configuration = true
    result_configuration {
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.athena.arn
      }
    }
  }
}
```

## Verification

```sh
`aws athena get-work-group --work-group <name> \
  --query 'WorkGroup.Configuration.ResultConfiguration.EncryptionConfiguration.EncryptionOption'`
must return `"SSE_KMS"`.
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**NIST CSF 2.0**
  - [`PR.DS-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-13`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-13)
  - [`SC-28`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-28)

**CSA CCM v4**
  - [`CEK-03`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AWS-ATHENA-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-ATHENA-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-ATHENA-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-ATHENA-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-ATHENA-001
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
