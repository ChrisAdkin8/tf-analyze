---
title: "INT-INTENT-004 — Prod-tagged resource has force_destroy=true"
description: "tf-analyze rule INT-INTENT-004 (HIGH · security): Prod-tagged resource has force_destroy=true"
keywords: "security, high, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "INT-INTENT-004 \u2014 Prod-tagged resource has force_destroy=true",
  "description": "Remove `force_destroy = true` from prod-tagged resources. Use\n`lifecycle { prevent_destroy = true }` instead.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/INT-INTENT-004/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/INT-INTENT-004/"
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

# ⚠️ INT-INTENT-004 — Prod-tagged resource has force_destroy=true

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/INT-INTENT-004" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Prod-tagged resource has force_destroy=true.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`intent_gap`** — _the variable-name suggests one intent but the resource configuration contradicts it._
  >

## Why it likely fired

>

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain INT-INTENT-004` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove `force_destroy = true` from prod-tagged resources. Use
`lifecycle { prevent_destroy = true }` instead.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_s3_bucket" "data" {
  bucket = "myorg-prod-data"
  tags   = { Environment = "prod" }
  # Remove: force_destroy = true
  lifecycle {
    prevent_destroy = true
  }
}
```

## Verification

Confirm no prod-tagged resource carries `force_destroy = true`.

## References

**Source**
  - [`catalog/INT-INTENT-004.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/INT-INTENT-004.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain INT-INTENT-004    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore INT-INTENT-004` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - INT-INTENT-004
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
