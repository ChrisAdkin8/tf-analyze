---
title: "ROB-AWS-RDS-001 — RDS instance or Aurora cluster backup retention disabled"
description: "tf-analyze rule ROB-AWS-RDS-001 (HIGH · robustness): RDS instance or Aurora cluster backup retention disabled"
keywords: "robustness, high, terraform, iac, aws, mitre-T1490, nist-csf-rc.rp-1, nist-800-53-cp-9, csa-ccm-bcr-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-AWS-RDS-001 \u2014 RDS instance or Aurora cluster backup retention disabled",
  "description": "Set `backup_retention_period` to at least `7` (days) on every\n`aws_db_instance`. For production databases, use `30` or more and also\nset `delete_automated_backups = false` so that automated backups survive\nan accidental instance deletion. W",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-RDS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-RDS-001/"
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
  "keywords": "robustness, high, terraform, MITRE T1490",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# ⚠️ ROB-AWS-RDS-001 — RDS instance or Aurora cluster backup retention disabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-AWS-RDS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-AWS-RDS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-AWS-RDS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **RDS instance or Aurora cluster backup retention disabled.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_db_instance` (`backup_retention_period`) matching `/^0$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  RDS instance with backup_retention_period = 0 (backups disabled)
2. **`resource_missing_arg`** on `aws_db_instance` (`backup_retention_period`) — _the resource is missing a required attribute (or nested attribute path)._
  RDS instance missing backup_retention_period (defaults to 0 for non-replica)
3. **`resource_arg`** on `aws_rds_cluster` (`backup_retention_period`) matching `/^0$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Aurora cluster with backup_retention_period = 0 (backups disabled)
4. **`resource_missing_arg`** on `aws_rds_cluster` (`backup_retention_period`) — _the resource is missing a required attribute (or nested attribute path)._
  Aurora cluster missing backup_retention_period (defaults to 1 but should be explicit)

## Why it likely fired

RDS instance with backup_retention_period = 0 (backups disabled)

RDS instance missing backup_retention_period (defaults to 0 for non-replica)

Aurora cluster with backup_retention_period = 0 (backups disabled)

Aurora cluster missing backup_retention_period (defaults to 1 but should be explicit)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-RDS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `backup_retention_period` to at least `7` (days) on every
`aws_db_instance`. For production databases, use `30` or more and also
set `delete_automated_backups = false` so that automated backups survive
an accidental instance deletion. Without backups, a corrupted or deleted
database cannot be recovered to a point-in-time prior to the incident.
Also consider enabling `copy_tags_to_snapshot = true` for cost allocation.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_db_instance" "example" {
  # ... other arguments ...
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
}
```

## Verification

Run `aws rds describe-db-instances --db-instance-identifier <id>` and
confirm `BackupRetentionPeriod` is greater than 0. Run `terraform plan`
and verify no diff shows `backup_retention_period = 0` or a missing value.

## References

**SOC 2 Trust Services Criteria**
  - `A1.2`

**MITRE ATT&CK**
  - [`T1490`](https://attack.mitre.org/techniques/T1490/)

**NIST CSF 2.0**
  - [`RC.RP-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CP-9`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cp-9)

**CSA CCM v4**
  - [`BCR-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/ROB-AWS-RDS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-RDS-001.yaml) — canonical YAML

## Family

See also rules in the `ROB-AWS-RDS-*` family:

- [`ROB-AWS-RDS-002`](./ROB-AWS-RDS-002.md) — RDS instance or Aurora cluster skips final snapshot on deletion
- [`ROB-AWS-RDS-003`](./ROB-AWS-RDS-003.md) — RDS instance or Aurora cluster missing deletion protection

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-RDS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-RDS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-RDS-001
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
