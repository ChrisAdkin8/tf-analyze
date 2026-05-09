---
title: "SEC-GCP-CLOUDRUN-001 — Cloud Run service allows all ingress traffic"
description: "tf-analyze rule SEC-GCP-CLOUDRUN-001 (HIGH · security): Cloud Run service allows all ingress traffic"
keywords: "security, high, terraform, iac, gcp"
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
  "keywords": "security, high, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-GCP-CLOUDRUN-001 — Cloud Run service allows all ingress traffic

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-CLOUDRUN-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

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

**Source**
  - [`catalog/SEC-GCP-CLOUDRUN-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-CLOUDRUN-001.yaml) — canonical YAML

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
