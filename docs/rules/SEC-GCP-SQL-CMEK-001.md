---
title: "SEC-GCP-SQL-CMEK-001 — Cloud SQL instance not encrypted with customer-managed key (CMEK)"
description: "tf-analyze rule SEC-GCP-SQL-CMEK-001 (MEDIUM · security): Cloud SQL instance not encrypted with customer-managed key (CMEK)"
keywords: "security, medium, terraform, iac, gcp, cis-6.7, mitre-T1530, cwe-311, d3-ear, nist-csf-pr.ds-1, nist-800-53-sc-12, nist-800-53-sc-13, csa-ccm-cek-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-SQL-CMEK-001 \u2014 Cloud SQL instance not encrypted with customer-managed key (CMEK)",
  "description": "Bind the instance to a Cloud KMS key in the same region. Grant the\nCloud SQL service identity `roles/cloudkms.cryptoKeyEncrypterDecrypter`\non the key first (via `google_kms_crypto_key_iam_member`):",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-SQL-CMEK-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-SQL-CMEK-001/"
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
  "keywords": "security, medium, terraform, CIS 6.7, MITRE T1530, CWE-311, D3-EAR",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-GCP-SQL-CMEK-001 — Cloud SQL instance not encrypted with customer-managed key (CMEK)

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-SQL-CMEK-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-SQL-CMEK-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-SQL-CMEK-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Cloud SQL instance not encrypted with customer-managed key (CMEK).** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_sql_database_instance` (`encryption_key_name`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_sql_database_instance` has no `encryption_key_name`. Without
a CMEK, Cloud SQL data is encrypted with a Google-managed key that
cannot be revoked or rotated independently. CIS 6.7 and PCI-DSS
Req-3.4 require customer-controlled key material for regulated
workloads.

## Why it likely fired

`google_sql_database_instance` has no `encryption_key_name`. Without
a CMEK, Cloud SQL data is encrypted with a Google-managed key that
cannot be revoked or rotated independently. CIS 6.7 and PCI-DSS
Req-3.4 require customer-controlled key material for regulated
workloads.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-SQL-CMEK-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Bind the instance to a Cloud KMS key in the same region. Grant the
Cloud SQL service identity `roles/cloudkms.cryptoKeyEncrypterDecrypter`
on the key first (via `google_kms_crypto_key_iam_member`):

    resource "google_sql_database_instance" "main" {
      # ...
      encryption_key_name = google_kms_crypto_key.sql.id
    }

Note: CMEK on Cloud SQL can only be configured at create-time;
existing instances must be cloned to a new CMEK-protected instance.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_sql_database_instance" "example" {
  name                = "example"
  region              = "us-central1"
  database_version    = "POSTGRES_16"
  encryption_key_name = google_kms_crypto_key.sql.id
  settings {
    tier = "db-custom-2-7680"
  }
}
```

_CMEK cannot be added in place; the instance must be recreated and data migrated._

## Verification

```sh
`gcloud sql instances describe <name> --format='value(diskEncryptionConfiguration.kmsKeyName)'`
must return a non-empty Cloud KMS key resource name.
```

## References

**CIS Benchmark**
  - `CIS 6.7`

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
  - [`catalog/SEC-GCP-SQL-CMEK-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-SQL-CMEK-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-SQL-CMEK-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-SQL-CMEK-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-SQL-CMEK-001
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
