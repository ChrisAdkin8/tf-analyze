---
title: "SEC-GCP-CLOUDRUN-003 — GCP Cloud Run service uses default compute service account"
description: "tf-analyze rule SEC-GCP-CLOUDRUN-003 (HIGH · security): GCP Cloud Run service uses default compute service account"
keywords: "security, high, terraform, iac, gcp, cis-1.4, mitre-T1078.004, cwe-250, nist-csf-pr.ac-4, nist-800-53-ac-6, csa-ccm-iam-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-CLOUDRUN-003 \u2014 GCP Cloud Run service uses default compute service account",
  "description": "Bind a dedicated service account with the minimum roles the service\nneeds:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-CLOUDRUN-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-CLOUDRUN-003/"
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
  "keywords": "security, high, terraform, CIS 1.4, MITRE T1078.004, CWE-250",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-GCP-CLOUDRUN-003 — GCP Cloud Run service uses default compute service account

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-CLOUDRUN-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-CLOUDRUN-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-CLOUDRUN-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Cloud Run service uses default compute service account.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_cloud_run_service` (`template.spec.service_account_name`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_cloud_run_service` has no
`template.spec.service_account_name`. The revision runs as the
project's default Compute Engine SA, which holds broad
`roles/editor`. A code-execution flaw inherits project-wide write
access.
2. **`resource_missing_arg`** on `google_cloud_run_v2_service` (`template.service_account`) — _the resource is missing a required attribute (or nested attribute path)._
  Cloud Run v2 service falls back to default compute SA

## Why it likely fired

`google_cloud_run_service` has no
`template.spec.service_account_name`. The revision runs as the
project's default Compute Engine SA, which holds broad
`roles/editor`. A code-execution flaw inherits project-wide write
access.

Cloud Run v2 service falls back to default compute SA

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-CLOUDRUN-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Bind a dedicated service account with the minimum roles the service
needs:

    resource "google_service_account" "run" {
      account_id = "run-frontend"
    }

    resource "google_cloud_run_v2_service" "main" {
      # ...
      template {
        service_account = google_service_account.run.email
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_cloud_run_v2_service" "example" {
  name     = "frontend"
  location = "us-central1"
  template {
    service_account = google_service_account.run.email
    containers { image = "gcr.io/example/app:1.0" }
  }
}
```

## Verification

```sh
`gcloud run services describe <name> --format='value(spec.template.spec.serviceAccountName)'`
must NOT return `<project-number>-compute@developer.gserviceaccount.com`.
```

## References

**CIS Benchmark**
  - `CIS 1.4`

**PCI-DSS**
  - `Req-7.1`

**SOC 2 Trust Services Criteria**
  - `CC6.3`

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**CWE**
  - [`CWE-250`](https://cwe.mitre.org/data/definitions/250.html)

**NIST CSF 2.0**
  - [`PR.AC-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-6`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-6)

**CSA CCM v4**
  - [`IAM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-CLOUDRUN-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-CLOUDRUN-003.yaml) — canonical YAML

## Family

See also rules in the `SEC-GCP-CLOUDRUN-*` family:

- [`SEC-GCP-CLOUDRUN-001`](./SEC-GCP-CLOUDRUN-001.md) — Cloud Run service allows all ingress traffic
- [`SEC-GCP-CLOUDRUN-002`](./SEC-GCP-CLOUDRUN-002.md) — GCP Cloud Run service publicly accessible (allUsers IAM binding)

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-CLOUDRUN-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-CLOUDRUN-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-CLOUDRUN-003
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
