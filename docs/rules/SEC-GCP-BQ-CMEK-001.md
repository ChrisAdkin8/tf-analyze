---
title: "SEC-GCP-BQ-CMEK-001 — BigQuery table not encrypted with customer-managed key"
description: "tf-analyze rule SEC-GCP-BQ-CMEK-001 (MEDIUM · security): BigQuery table not encrypted with customer-managed key"
keywords: "security, medium, terraform, iac, gcp, mitre-T1530, cwe-311, d3-ear, nist-csf-pr.ds-1, nist-800-53-sc-12, nist-800-53-sc-13, csa-ccm-cek-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-BQ-CMEK-001 \u2014 BigQuery table not encrypted with customer-managed key",
  "description": "Set encryption_configuration on tables holding sensitive data:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-BQ-CMEK-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-BQ-CMEK-001/"
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

# 💡 SEC-GCP-BQ-CMEK-001 — BigQuery table not encrypted with customer-managed key

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-BQ-CMEK-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-BQ-CMEK-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-BQ-CMEK-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **BigQuery table not encrypted with customer-managed key.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_bigquery_table` (`encryption_configuration`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_bigquery_table` has no `encryption_configuration`. The
table inherits the dataset's encryption — which defaults to a
Google-managed key unless the dataset has
`default_encryption_configuration.kms_key_name` set.

## Why it likely fired

`google_bigquery_table` has no `encryption_configuration`. The
table inherits the dataset's encryption — which defaults to a
Google-managed key unless the dataset has
`default_encryption_configuration.kms_key_name` set.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-BQ-CMEK-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set encryption_configuration on tables holding sensitive data:

    resource "google_bigquery_table" "main" {
      # ...
      encryption_configuration {
        kms_key_name = google_kms_crypto_key.bq.id
      }
    }

Or set `default_encryption_configuration` at the dataset level so
every new table inherits CMEK.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_bigquery_table" "example" {
  dataset_id = google_bigquery_dataset.example.dataset_id
  table_id   = "example"
  encryption_configuration {
    kms_key_name = "projects/example/locations/us/keyRings/bq/cryptoKeys/data"
  }
}
```

## Verification

```sh
`bq show --format=prettyjson <project>:<dataset>.<table> | \
  jq '.encryptionConfiguration.kmsKeyName'` must return a non-null
Cloud KMS key URI.
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

**NIST CSF 2.0**
  - [`PR.DS-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-12`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-12)
  - [`SC-13`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-13)

**CSA CCM v4**
  - [`CEK-03`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-BQ-CMEK-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-BQ-CMEK-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-BQ-CMEK-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-BQ-CMEK-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-BQ-CMEK-001
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
