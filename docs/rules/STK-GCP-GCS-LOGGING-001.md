---
title: "STK-GCP-GCS-LOGGING-001 — GCS bucket logging target lacks public_access_prevention"
description: "tf-analyze rule STK-GCP-GCS-LOGGING-001 (HIGH · stack): GCS bucket logging target lacks public_access_prevention"
keywords: "stack, high, terraform, iac, gcp, cis-5.1"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-GCS-LOGGING-001 \u2014 GCS bucket logging target lacks public_access_prevention",
  "description": "Add `public_access_prevention = \"enforced\"` to the target bucket\nblock. Also confirm `uniform_bucket_level_access = true` and that no\nIAM binding grants `allUsers` or `allAuthenticatedUsers` access. If\nthe source and target bucket have diff",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-GCS-LOGGING-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-GCS-LOGGING-001/"
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
  "keywords": "stack, high, terraform, CIS 5.1",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-GCP-GCS-LOGGING-001 — GCS bucket logging target lacks public_access_prevention

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-GCS-LOGGING-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCS bucket logging target lacks public_access_prevention.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`graph_check`** — _a corpus-wide graph check fired (cross-resource invariant)._
  A `google_storage_bucket` references another bucket via
`logging.log_bucket = google_storage_bucket.<x>.name`, but that
target bucket does not set `public_access_prevention = "enforced"`.
Logging targets accumulate access records for every read/write on
the source bucket; if the target is publicly readable, an attacker
can enumerate which objects exist and how often they're read.

## Why it likely fired

A `google_storage_bucket` references another bucket via
`logging.log_bucket = google_storage_bucket.<x>.name`, but that
target bucket does not set `public_access_prevention = "enforced"`.
Logging targets accumulate access records for every read/write on
the source bucket; if the target is publicly readable, an attacker
can enumerate which objects exist and how often they're read.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-GCS-LOGGING-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `public_access_prevention = "enforced"` to the target bucket
block. Also confirm `uniform_bucket_level_access = true` and that no
IAM binding grants `allUsers` or `allAuthenticatedUsers` access. If
the source and target bucket have different blast-radius requirements
(e.g., source is internal, target is shared with auditors), document
the rationale in a comment near the `logging` block so the next
reviewer doesn't downgrade it.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_storage_bucket" "logs" {
  name                        = "example-logs"
  location                    = "US"
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true
  lifecycle_rule {
    condition { age = 90 }
    action { type = "Delete" }
  }
}
```

## Verification

After applying the fix, run:

    gcloud storage buckets describe gs://<target> --format='value(publicAccessPrevention)'

and confirm it prints `enforced`. Re-run tf-analyze; STK-GCS-LOGGING-001
should not fire.

## References

**CIS Benchmark**
  - `CIS 5.1`

**Related rules**
  - [`SEC-BUCKET-001`](./SEC-BUCKET-001.md)
  - [`SEC-BUCKET-002`](./SEC-BUCKET-002.md)

**Source**
  - [`catalog/STK-GCP-GCS-LOGGING-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-GCS-LOGGING-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-GCS-LOGGING-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-GCS-LOGGING-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-GCS-LOGGING-001
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
