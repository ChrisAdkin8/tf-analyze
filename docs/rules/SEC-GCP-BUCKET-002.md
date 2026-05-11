---
title: "SEC-GCP-BUCKET-002 — GCS bucket missing uniform_bucket_level_access"
description: "tf-analyze rule SEC-GCP-BUCKET-002 (MEDIUM · security): GCS bucket missing uniform_bucket_level_access"
keywords: "security, medium, terraform, iac, gcp, cis-5.2, mitre-T1530, cwe-732, cwe-284, nist-csf-pr.ds-1, nist-800-53-sc-13, nist-800-53-sc-28, csa-ccm-cek-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-BUCKET-002 \u2014 GCS bucket missing uniform_bucket_level_access",
  "description": "Set `uniform_bucket_level_access = true`. ACLs are legacy and should\nnot coexist with IAM bindings.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-BUCKET-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-BUCKET-002/"
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
  "keywords": "security, medium, terraform, CIS 5.2, MITRE T1530, CWE-732, CWE-284",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-GCP-BUCKET-002 — GCS bucket missing uniform_bucket_level_access

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-BUCKET-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-BUCKET-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-BUCKET-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCS bucket missing uniform_bucket_level_access.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_storage_bucket` (`uniform_bucket_level_access`) — _the resource is missing a required attribute (or nested attribute path)._
2. **`hcl_attr`** on `google_storage_bucket` (`uniform_bucket_level_access`) not equal to `True` — _an attribute value differs from the expected literal._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-BUCKET-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `uniform_bucket_level_access = true`. ACLs are legacy and should
not coexist with IAM bindings.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_storage_bucket" "example" {
  name                        = "example"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}
```

## Verification

After applying, run `gcloud storage buckets describe gs://<bucket>
--format='value(iamConfiguration.uniformBucketLevelAccess.enabled)'`.

## References

**CIS Benchmark**
  - `CIS 5.2`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**CWE**
  - [`CWE-732`](https://cwe.mitre.org/data/definitions/732.html)
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**NIST CSF 2.0**
  - [`PR.DS-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-13`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-13)
  - [`SC-28`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-28)

**CSA CCM v4**
  - [`CEK-03`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-BUCKET-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-BUCKET-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-GCP-BUCKET-*` family:

- [`SEC-GCP-BUCKET-001`](./SEC-GCP-BUCKET-001.md) — GCS bucket missing public_access_prevention=enforced

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-BUCKET-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-BUCKET-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-BUCKET-002
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
