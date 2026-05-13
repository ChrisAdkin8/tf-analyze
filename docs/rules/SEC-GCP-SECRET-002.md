---
title: "SEC-GCP-SECRET-002 — GCP Secret Manager secret without CMEK on user-managed replication"
description: "tf-analyze rule SEC-GCP-SECRET-002 (MEDIUM · security): GCP Secret Manager secret without CMEK on user-managed replication"
keywords: "security, medium, terraform, iac, gcp, mitre-T1552.001, cwe-311, d3-ear, nist-csf-pr.ds-1, nist-800-53-sc-12, nist-800-53-sc-13, csa-ccm-cek-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-SECRET-002 \u2014 GCP Secret Manager secret without CMEK on user-managed replication",
  "description": "Switch to user-managed replication with CMEK:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-SECRET-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-SECRET-002/"
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
  "keywords": "security, medium, terraform, MITRE T1552.001, CWE-311, D3-EAR",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-GCP-SECRET-002 — GCP Secret Manager secret without CMEK on user-managed replication

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-SECRET-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-SECRET-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-SECRET-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Secret Manager secret without CMEK on user-managed replication.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_body_contains`** on `google_secret_manager_secret` matching `/replication\s*\{\s*auto\s*\{\s*\}\s*\}/` — _the resource body matches a regex inside the block._
  `google_secret_manager_secret` uses `replication.auto`, which is
encrypted with a Google-managed key. CMEK requires explicit
`replication.user_managed` with `customer_managed_encryption.kms_key_name`
per replica.

## Why it likely fired

`google_secret_manager_secret` uses `replication.auto`, which is
encrypted with a Google-managed key. CMEK requires explicit
`replication.user_managed` with `customer_managed_encryption.kms_key_name`
per replica.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-SECRET-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Switch to user-managed replication with CMEK:

    resource "google_secret_manager_secret" "db_pw" {
      secret_id = "db-pw"
      replication {
        user_managed {
          replicas {
            location = "us-central1"
            customer_managed_encryption {
              kms_key_name = google_kms_crypto_key.secrets.id
            }
          }
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_secret_manager_secret" "example" {
  secret_id = "example"
  replication {
    user_managed {
      replicas {
        location = "us-central1"
        customer_managed_encryption {
          kms_key_name = "projects/example/locations/us-central1/keyRings/r/cryptoKeys/k"
        }
      }
    }
  }
}
```

## Verification

```sh
`gcloud secrets describe <name> --format=json | jq '.replication.userManaged.replicas[].customerManagedEncryption.kmsKeyName'`
must return non-null KMS key names for every replica.
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)

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
  - [`catalog/SEC-GCP-SECRET-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-SECRET-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-GCP-SECRET-*` family:

- [`SEC-GCP-SECRET-001`](./SEC-GCP-SECRET-001.md) — GCP Secret Manager secret has no rotation configured

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-SECRET-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-SECRET-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-SECRET-002
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
