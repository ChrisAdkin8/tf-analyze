---
title: "ROB-AWS-BACKUP-001 — No AWS Backup plan defined"
description: "tf-analyze rule ROB-AWS-BACKUP-001 (MEDIUM · robustness): No AWS Backup plan defined"
keywords: "robustness, medium, terraform, iac, aws"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-AWS-BACKUP-001 \u2014 No AWS Backup plan defined",
  "description": "Define a backup plan with appropriate retention:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-BACKUP-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-BACKUP-001/"
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

# 💡 ROB-AWS-BACKUP-001 — No AWS Backup plan defined

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-AWS-BACKUP-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-AWS-BACKUP-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-AWS-BACKUP-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **No AWS Backup plan defined.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`resource_absent`** on `aws_backup_plan` — _the corpus is missing a resource type we expected to find given other resources present._
  No `aws_backup_plan` is defined in this Terraform configuration.
Without a backup plan, data on EBS volumes, RDS databases, DynamoDB tables,
and EFS file systems is not protected by automated backups. Recovery from
accidental deletion or ransomware requires either a manual ad-hoc backup
(slow, error-prone) or a prior backup taken outside this plan.

## Why it likely fired

No `aws_backup_plan` is defined in this Terraform configuration.
Without a backup plan, data on EBS volumes, RDS databases, DynamoDB tables,
and EFS file systems is not protected by automated backups. Recovery from
accidental deletion or ransomware requires either a manual ad-hoc backup
(slow, error-prone) or a prior backup taken outside this plan.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-BACKUP-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Define a backup plan with appropriate retention:

    resource "aws_backup_plan" "main" {
      name = "main"

      rule {
        rule_name         = "daily_30d"
        target_vault_name = aws_backup_vault.main.name
        schedule          = "cron(0 5 ? * * *)"

        lifecycle {
          delete_after = 30
        }

        copy_action {
          destination_vault_arn = aws_backup_vault.dr_region.arn
          lifecycle { delete_after = 90 }
        }
      }
    }

    resource "aws_backup_selection" "all_tagged" {
      plan_id      = aws_backup_plan.main.id
      name         = "all_tagged_resources"
      iam_role_arn = aws_iam_role.backup.arn

      selection_tag {
        type  = "STRINGEQUALS"
        key   = "backup"
        value = "true"
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_backup_plan" "example" {
  name = "example"
  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.example.name
    schedule          = "cron(0 5 ? * * *)"
    lifecycle { delete_after = 30 }
  }
}
```

## Verification

```sh
`aws backup list-backup-plans --query 'BackupPlansList[*].BackupPlanName'`
must return at least one plan.
```

## References

**PCI-DSS**
  - `Req-9.5`

**SOC 2 Trust Services Criteria**
  - `A1.2`

**Source**
  - [`catalog/ROB-AWS-BACKUP-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-BACKUP-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-BACKUP-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-BACKUP-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-BACKUP-001
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
