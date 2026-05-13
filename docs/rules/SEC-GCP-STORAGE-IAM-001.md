---
title: "SEC-GCP-STORAGE-IAM-001 — GCS bucket bound to allUsers or allAuthenticatedUsers"
description: "tf-analyze rule SEC-GCP-STORAGE-IAM-001 (CRITICAL · security): GCS bucket bound to allUsers or allAuthenticatedUsers"
keywords: "security, critical, terraform, iac, gcp, cis-5.1, mitre-T1530, cwe-284, d3-uac, nist-csf-pr.ac-3, nist-800-53-ac-3, csa-ccm-iam-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-STORAGE-IAM-001 \u2014 GCS bucket bound to allUsers or allAuthenticatedUsers",
  "description": "Replace the public principal with an authenticated identity:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-STORAGE-IAM-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-STORAGE-IAM-001/"
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
  "keywords": "security, critical, terraform, CIS 5.1, MITRE T1530, CWE-284, D3-UAC",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-GCP-STORAGE-IAM-001 — GCS bucket bound to allUsers or allAuthenticatedUsers

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-STORAGE-IAM-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-STORAGE-IAM-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-STORAGE-IAM-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCS bucket bound to allUsers or allAuthenticatedUsers.** This rule has `default_urgency: CRITICAL` and operates on a single resource blast radius. 

## What this checks

1. **`resource_body_contains`** on `google_storage_bucket_iam_member` matching `/member\s*=\s*"all(Users|AuthenticatedUsers)"/` — _the resource body matches a regex inside the block._
  `google_storage_bucket_iam_member` binds the bucket to `allUsers`
or `allAuthenticatedUsers`. Bucket contents become world-readable
(or writable, depending on the role). The equivalent of
`SEC-AWS-S3-PUBLIC-BLOCK-001`.
2. **`resource_body_contains`** on `google_storage_bucket_iam_binding` matching `/members\s*=\s*\[[^\]]*"all(Users|AuthenticatedUsers)"/` — _the resource body matches a regex inside the block._
  GCS bucket IAM binding includes allUsers / allAuthenticatedUsers

## Why it likely fired

`google_storage_bucket_iam_member` binds the bucket to `allUsers`
or `allAuthenticatedUsers`. Bucket contents become world-readable
(or writable, depending on the role). The equivalent of
`SEC-AWS-S3-PUBLIC-BLOCK-001`.

GCS bucket IAM binding includes allUsers / allAuthenticatedUsers

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-STORAGE-IAM-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace the public principal with an authenticated identity:

    resource "google_storage_bucket_iam_member" "viewer" {
      bucket = google_storage_bucket.main.name
      role   = "roles/storage.objectViewer"
      member = "group:viewers@example.com"
    }

If genuinely public data is required, prefer `public_access_prevention = "inherited"`
combined with documented Cloud CDN distribution.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_storage_bucket_iam_member" "example" {
  bucket = google_storage_bucket.example.name
  role   = "roles/storage.objectViewer"
  member = "group:viewers@example.com"
}
```

## Verification

```sh
`gsutil iam get gs://<bucket>` must not list `allUsers` or
`allAuthenticatedUsers` for any role.
```

## References

**CIS Benchmark**
  - `CIS 5.1`

**PCI-DSS**
  - `Req-7.1`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**MITRE D3FEND**
  - [`D3-UAC`](https://d3fend.mitre.org/technique/D3-UAC/)

**NIST CSF 2.0**
  - [`PR.AC-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-3)

**CSA CCM v4**
  - [`IAM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-STORAGE-IAM-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-STORAGE-IAM-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-STORAGE-IAM-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-STORAGE-IAM-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-STORAGE-IAM-001
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
