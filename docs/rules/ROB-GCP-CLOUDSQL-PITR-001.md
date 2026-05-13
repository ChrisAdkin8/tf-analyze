---
title: "ROB-GCP-CLOUDSQL-PITR-001 — Cloud SQL instance missing point-in-time recovery"
description: "tf-analyze rule ROB-GCP-CLOUDSQL-PITR-001 (MEDIUM · robustness): Cloud SQL instance missing point-in-time recovery"
keywords: "robustness, medium, terraform, iac, gcp, cis-6.6, mitre-T1485, mitre-T1490, cwe-779, d3-dencr, nist-csf-pr.ip-4, nist-800-53-cp-9, csa-ccm-bcr-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-GCP-CLOUDSQL-PITR-001 \u2014 Cloud SQL instance missing point-in-time recovery",
  "description": "Enable PITR (Postgres / MySQL only):",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-GCP-CLOUDSQL-PITR-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-GCP-CLOUDSQL-PITR-001/"
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
  "keywords": "robustness, medium, terraform, CIS 6.6, MITRE T1485, MITRE T1490, CWE-779, D3-DENCR",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# 💡 ROB-GCP-CLOUDSQL-PITR-001 — Cloud SQL instance missing point-in-time recovery

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-GCP-CLOUDSQL-PITR-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-GCP-CLOUDSQL-PITR-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-GCP-CLOUDSQL-PITR-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Cloud SQL instance missing point-in-time recovery.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_body_contains`** on `google_sql_database_instance` matching `/point_in_time_recovery_enabled\s*=\s*false/` — _the resource body matches a regex inside the block._
  `google_sql_database_instance.settings.backup_configuration.point_in_time_recovery_enabled`
is `false`. Without PITR, recovery is limited to nightly snapshot
granularity — any incident between snapshots loses up to 24h of
writes. Equivalent to AWS RDS PITR gap.

## Why it likely fired

`google_sql_database_instance.settings.backup_configuration.point_in_time_recovery_enabled`
is `false`. Without PITR, recovery is limited to nightly snapshot
granularity — any incident between snapshots loses up to 24h of
writes. Equivalent to AWS RDS PITR gap.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-GCP-CLOUDSQL-PITR-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable PITR (Postgres / MySQL only):

    resource "google_sql_database_instance" "main" {
      # ...
      settings {
        backup_configuration {
          enabled                        = true
          point_in_time_recovery_enabled = true
          transaction_log_retention_days = 7
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_sql_database_instance" "example" {
  name             = "example"
  region           = "us-central1"
  database_version = "POSTGRES_16"
  settings {
    tier = "db-custom-2-7680"
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
    }
  }
}
```

## Verification

```sh
`gcloud sql instances describe <name> --format='value(settings.backupConfiguration.pointInTimeRecoveryEnabled)'`
must return `True`.
```

## References

**CIS Benchmark**
  - `CIS 6.6`

**PCI-DSS**
  - `Req-3.1`

**SOC 2 Trust Services Criteria**
  - `A1.2`

**MITRE ATT&CK**
  - [`T1485`](https://attack.mitre.org/techniques/T1485/)
  - [`T1490`](https://attack.mitre.org/techniques/T1490/)

**CWE**
  - [`CWE-779`](https://cwe.mitre.org/data/definitions/779.html)

**MITRE D3FEND**
  - [`D3-DENCR`](https://d3fend.mitre.org/technique/D3-DENCR/)

**NIST CSF 2.0**
  - [`PR.IP-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CP-9`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cp-9)

**CSA CCM v4**
  - [`BCR-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/ROB-GCP-CLOUDSQL-PITR-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-GCP-CLOUDSQL-PITR-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-GCP-CLOUDSQL-PITR-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-GCP-CLOUDSQL-PITR-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-GCP-CLOUDSQL-PITR-001
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
