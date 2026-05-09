---
title: "SEC-AWS-BACKUP-001 — Backup vault uses AWS-managed key (no CMK)"
description: "tf-analyze rule SEC-AWS-BACKUP-001 (MEDIUM · security): Backup vault uses AWS-managed key (no CMK)"
keywords: "security, medium, terraform, iac, aws"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-BACKUP-001 \u2014 Backup vault uses AWS-managed key (no CMK)",
  "description": "Specify a customer-managed KMS key for the backup vault:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-BACKUP-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-BACKUP-001/"
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

# 💡 SEC-AWS-BACKUP-001 — Backup vault uses AWS-managed key (no CMK)

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-BACKUP-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Backup vault uses AWS-managed key (no CMK).** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_backup_vault` (`kms_key_arn`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_backup_vault` has no `kms_key_arn`. Backup vaults encrypt recovery
points by default using the AWS-managed key (`aws/backup`), which cannot
be restricted or rotated on demand. A customer-managed KMS key enables
key policy enforcement, access auditing, and independent key lifecycle
management. Without a CMK, anyone with `backup:GetRecoveryPointRestoreMetadata`
can decrypt backup data using the shared AWS key.

## Why it likely fired

`aws_backup_vault` has no `kms_key_arn`. Backup vaults encrypt recovery
points by default using the AWS-managed key (`aws/backup`), which cannot
be restricted or rotated on demand. A customer-managed KMS key enables
key policy enforcement, access auditing, and independent key lifecycle
management. Without a CMK, anyone with `backup:GetRecoveryPointRestoreMetadata`
can decrypt backup data using the shared AWS key.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-BACKUP-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Specify a customer-managed KMS key for the backup vault:

    resource "aws_backup_vault" "main" {
      name        = "main"
      kms_key_arn = aws_kms_key.backup.arn
    }

    resource "aws_kms_key" "backup" {
      description             = "CMK for AWS Backup vault"
      enable_key_rotation     = true
      deletion_window_in_days = 30
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "aws_backup_vault" "example" {
  name        = "example"
  kms_key_arn = aws_kms_key.backup.arn
}
```

## Verification

```sh
`aws backup describe-backup-vault --backup-vault-name <name> \
  --query 'EncryptionKeyArn'`
must return your CMK ARN, not arn:aws:kms:...:alias/aws/backup.
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**Source**
  - [`catalog/SEC-AWS-BACKUP-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-BACKUP-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-BACKUP-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-BACKUP-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-BACKUP-001
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
