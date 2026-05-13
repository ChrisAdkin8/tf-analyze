---
title: "SEC-GCP-CLOUDRUN-001 — Cloud Run service allows all ingress traffic"
description: "tf-analyze rule SEC-GCP-CLOUDRUN-001 (HIGH · security): Cloud Run service allows all ingress traffic"
keywords: "security, high, terraform, iac, gcp, mitre-T1190, cwe-284, d3-iaa, nist-csf-pr.ac-3, nist-800-53-sc-7, csa-ccm-ivs-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-CLOUDRUN-001 \u2014 Cloud Run service allows all ingress traffic",
  "description": "Restrict ingress to internal traffic or load-balancer-only:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-CLOUDRUN-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-CLOUDRUN-001/"
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
  "keywords": "security, high, terraform, MITRE T1190, CWE-284, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-GCP-CLOUDRUN-001 — Cloud Run service allows all ingress traffic

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-CLOUDRUN-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-CLOUDRUN-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-CLOUDRUN-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Cloud Run service allows all ingress traffic.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `google_cloud_run_v2_service` (`ingress`) matching `/INGRESS_TRAFFIC_ALL/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `google_cloud_run_v2_service` with `ingress = "INGRESS_TRAFFIC_ALL"`
accepts requests from the public internet with no VPC or load-balancer
restriction.

## Why it likely fired

`google_cloud_run_v2_service` with `ingress = "INGRESS_TRAFFIC_ALL"`
accepts requests from the public internet with no VPC or load-balancer
restriction.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-CLOUDRUN-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Restrict ingress to internal traffic or load-balancer-only:

    resource "google_cloud_run_v2_service" "app" {
      # ...
      ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
    }

Options:
- `INGRESS_TRAFFIC_INTERNAL_ONLY` — VPC-only, no public access
- `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER` — load balancer + VPC (recommended for public APIs with WAF/CDN)
- `INGRESS_TRAFFIC_ALL` — public internet (only for genuinely public, unauthenticated endpoints)

Pair with `google_cloud_run_v2_service_iam_member` if authentication
is required.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_cloud_run_v2_service" "example" {
  name     = "example"
  location = "us-central1"
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  template {
    containers {
      image = "gcr.io/example/app:latest"
    }
  }
}
```

## Verification

```sh
`gcloud run services describe <name> --region <region> \
  --format='value(metadata.annotations[run.googleapis.com/ingress])'`
must not return `all`.
```

## References

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**MITRE D3FEND**
  - [`D3-IAA`](https://d3fend.mitre.org/technique/D3-IAA/)

**NIST CSF 2.0**
  - [`PR.AC-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-7)

**CSA CCM v4**
  - [`IVS-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-CLOUDRUN-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-CLOUDRUN-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-GCP-CLOUDRUN-*` family:

- [`SEC-GCP-CLOUDRUN-002`](./SEC-GCP-CLOUDRUN-002.md) — GCP Cloud Run service publicly accessible (allUsers IAM binding)
- [`SEC-GCP-CLOUDRUN-003`](./SEC-GCP-CLOUDRUN-003.md) — GCP Cloud Run service uses default compute service account

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-CLOUDRUN-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-CLOUDRUN-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-CLOUDRUN-001
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
