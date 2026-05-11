---
title: "STK-GCP-CLOUDSQL-005 — Cloud SQL instance uses end-of-life database version"
description: "tf-analyze rule STK-GCP-CLOUDSQL-005 (HIGH · stack): Cloud SQL instance uses end-of-life database version"
keywords: "stack, high, terraform, iac, gcp, mitre-T1190, mitre-T1195.002, cwe-1104, d3-sca, nist-csf-id.sc-2, nist-800-53-sr-4, csa-ccm-ais-07, slsa-deps"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-CLOUDSQL-005 \u2014 Cloud SQL instance uses end-of-life database version",
  "description": "Upgrade to a supported version. Current Google Cloud SQL supported versions:\n- PostgreSQL: 14, 15, 16\n- MySQL: 8.0, 8.4\n- SQL Server: 2017, 2019, 2022",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-CLOUDSQL-005/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-CLOUDSQL-005/"
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
  "keywords": "stack, high, terraform, MITRE T1190, MITRE T1195.002, CWE-1104, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-GCP-CLOUDSQL-005 — Cloud SQL instance uses end-of-life database version

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-CLOUDSQL-005" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-CLOUDSQL-005" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-CLOUDSQL-005 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Cloud SQL instance uses end-of-life database version.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `google_sql_database_instance` (`database_version`) matching `/^(POSTGRES_9_6|MYSQL_5_6|MYSQL_5_7|SQLSERVER_2012|SQLSERVER_2014)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `database_version` set to a version that has reached end-of-life and
no longer receives security patches from the upstream project or Google.

## Why it likely fired

`database_version` set to a version that has reached end-of-life and
no longer receives security patches from the upstream project or Google.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-CLOUDSQL-005` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Upgrade to a supported version. Current Google Cloud SQL supported versions:
- PostgreSQL: 14, 15, 16
- MySQL: 8.0, 8.4
- SQL Server: 2017, 2019, 2022

Test the upgrade on a clone first:
    resource "google_sql_database_instance" "clone" {
      database_version = "POSTGRES_15"
      clone { source_instance_name = google_sql_database_instance.main.name }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_sql_database_instance" "example" {
  name             = "example"
  database_version = "POSTGRES_16"
  settings {
    tier = "db-f1-micro"
  }
}
```

## Verification

```sh
`gcloud sql instances describe <name> --format='value(databaseVersion)'`
must return a supported, non-EOL version string.
```

## References

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1104`](https://cwe.mitre.org/data/definitions/1104.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**NIST CSF 2.0**
  - [`ID.SC-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SR-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-4)

**CSA CCM v4**
  - [`AIS-07`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**SLSA v1.0**
  - [`SLSA deps`](https://slsa.dev/spec/v1.0/deps-track)

**Source**
  - [`catalog/STK-GCP-CLOUDSQL-005.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-CLOUDSQL-005.yaml) — canonical YAML

## Family

See also rules in the `STK-GCP-CLOUDSQL-*` family:

- [`STK-GCP-CLOUDSQL-001`](./STK-GCP-CLOUDSQL-001.md) — Cloud SQL instance missing backup_configuration
- [`STK-GCP-CLOUDSQL-003`](./STK-GCP-CLOUDSQL-003.md) — Cloud SQL instance missing deletion protection
- [`STK-GCP-CLOUDSQL-004`](./STK-GCP-CLOUDSQL-004.md) — Cloud SQL instance does not require SSL connections

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-CLOUDSQL-005    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-CLOUDSQL-005` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-CLOUDSQL-005
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
