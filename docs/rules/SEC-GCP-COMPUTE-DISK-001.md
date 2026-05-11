---
title: "SEC-GCP-COMPUTE-DISK-001 — GCP compute disk not encrypted with CSEK/CMEK"
description: "tf-analyze rule SEC-GCP-COMPUTE-DISK-001 (MEDIUM · security): GCP compute disk not encrypted with CSEK/CMEK"
keywords: "security, medium, terraform, iac, gcp, mitre-T1530, cwe-311, d3-ear, nist-csf-pr.ds-1, nist-800-53-sc-13, nist-800-53-sc-28, csa-ccm-cek-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-COMPUTE-DISK-001 \u2014 GCP compute disk not encrypted with CSEK/CMEK",
  "description": "Specify a KMS key for disk encryption:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-COMPUTE-DISK-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-COMPUTE-DISK-001/"
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

# 💡 SEC-GCP-COMPUTE-DISK-001 — GCP compute disk not encrypted with CSEK/CMEK

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-COMPUTE-DISK-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-COMPUTE-DISK-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-COMPUTE-DISK-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP compute disk not encrypted with CSEK/CMEK.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_compute_disk` (`disk_encryption_key`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_compute_disk` has no `disk_encryption_key` block. Without a
customer-managed encryption key (CMEK) or customer-supplied encryption
key (CSEK), the disk is encrypted with a Google-managed key. This
prevents independent key rotation, key revocation for incident response,
and satisfying compliance requirements that mandate customer-controlled
encryption.
2. **`resource_missing_arg`** on `google_compute_instance` (`disk_encryption_key`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_compute_instance` boot disk has no `disk_encryption_key_raw`.
The boot disk defaults to Google-managed encryption.

## Why it likely fired

`google_compute_disk` has no `disk_encryption_key` block. Without a
customer-managed encryption key (CMEK) or customer-supplied encryption
key (CSEK), the disk is encrypted with a Google-managed key. This
prevents independent key rotation, key revocation for incident response,
and satisfying compliance requirements that mandate customer-controlled
encryption.

`google_compute_instance` boot disk has no `disk_encryption_key_raw`.
The boot disk defaults to Google-managed encryption.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-COMPUTE-DISK-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Specify a KMS key for disk encryption:

    resource "google_compute_disk" "data" {
      name = "data"
      type = "pd-ssd"
      zone = "us-central1-a"

      disk_encryption_key {
        kms_key_self_link = google_kms_crypto_key.disk.id
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_compute_disk" "example" {
  name = "example"
  type = "pd-ssd"
  zone = "us-central1-a"
  disk_encryption_key {
    kms_key_self_link = google_kms_crypto_key.disk.id
  }
}
```

## Verification

```sh
`gcloud compute disks describe <name> --zone <zone> \
  --format='get(diskEncryptionKey.kmsKeyName)'`
must return a KMS key resource path.
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
  - [`SC-13`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-13)
  - [`SC-28`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-28)

**CSA CCM v4**
  - [`CEK-03`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-COMPUTE-DISK-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-COMPUTE-DISK-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-COMPUTE-DISK-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-COMPUTE-DISK-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-COMPUTE-DISK-001
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
