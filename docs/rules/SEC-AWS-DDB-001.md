---
title: "SEC-AWS-DDB-001 — DynamoDB table not using customer-managed KMS key for encryption"
description: "tf-analyze rule SEC-AWS-DDB-001 (MEDIUM · security): DynamoDB table not using customer-managed KMS key for encryption"
keywords: "security, medium, terraform, iac, aws, mitre-T1530, cwe-311, d3-ear"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-DDB-001 \u2014 DynamoDB table not using customer-managed KMS key for encryption",
  "description": "Add a `server_side_encryption` block with a customer-managed KMS key:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-DDB-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-DDB-001/"
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
  "keywords": "security, medium, terraform, MITRE T1530, CWE-311, D3-EAR",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AWS-DDB-001 — DynamoDB table not using customer-managed KMS key for encryption

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-DDB-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-DDB-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-DDB-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **DynamoDB table not using customer-managed KMS key for encryption.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`graph_check`** — _a corpus-wide graph check fired (cross-resource invariant)._
  `aws_dynamodb_table` without a `server_side_encryption` block
specifying a `kms_key_arn`. DynamoDB encrypts at rest by default
using Amazon-owned keys, but these keys cannot be audited, rotated,
or revoked. Customer-managed KMS keys (CMKs) provide key usage audit
trails in CloudTrail, cross-account access control, and automatic
annual rotation.

## Why it likely fired

`aws_dynamodb_table` without a `server_side_encryption` block
specifying a `kms_key_arn`. DynamoDB encrypts at rest by default
using Amazon-owned keys, but these keys cannot be audited, rotated,
or revoked. Customer-managed KMS keys (CMKs) provide key usage audit
trails in CloudTrail, cross-account access control, and automatic
annual rotation.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-DDB-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `server_side_encryption` block with a customer-managed KMS key:

    resource "aws_kms_key" "ddb" {
      description             = "DynamoDB table CMK"
      deletion_window_in_days = 30
      enable_key_rotation     = true
    }

    resource "aws_dynamodb_table" "app" {
      name = "app"

      server_side_encryption {
        enabled     = true
        kms_key_arn = aws_kms_key.ddb.arn
      }
    }

If a CMK is not yet available, the minimum acceptable baseline is
`server_side_encryption { enabled = true }` (AWS-managed key), which
at least makes the encryption choice explicit rather than implicit.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_dynamodb_table" "example" {
  name = "example"

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.ddb.arn
  }
}
```

## Verification

```sh
`aws dynamodb describe-table --table-name <name> \
  --query 'Table.SSEDescription'`
must return `Status: ENABLED` with a `KMSMasterKeyArn` value pointing
to a customer-managed key (not the AWS-owned key ARN).
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**CWE**
  - [`CWE-311`](https://cwe.mitre.org/data/definitions/311.html)

**MITRE D3FEND**
  - [`D3-EAR`](https://d3fend.mitre.org/technique/D3-EAR/)

**Source**
  - [`catalog/SEC-AWS-DDB-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-DDB-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-DDB-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-DDB-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-DDB-001
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
