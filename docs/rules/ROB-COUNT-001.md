---
title: "ROB-COUNT-001 — Boolean count pattern instead of for_each"
description: "tf-analyze rule ROB-COUNT-001 (LOW · robustness): Boolean count pattern instead of for_each"
keywords: "robustness, low, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-COUNT-001 \u2014 Boolean count pattern instead of for_each",
  "description": "Replace `count = var.enabled ? 1 : 0` with:\n```hcl\nfor_each = var.enabled ? toset([\"this\"]) : toset([])\n```\nThe `for_each` approach produces map-keyed instances (`resource[\"this\"]`)\ninstead of list-indexed ones (`resource[0]`). This elimina",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-COUNT-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-COUNT-001/"
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
  "keywords": "robustness, low, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# ℹ️ ROB-COUNT-001 — Boolean count pattern instead of for_each

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-COUNT-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Boolean count pattern instead of for_each.** This rule has `default_urgency: LOW` and operates on a single resource blast radius. 

## What this checks

1. **`count_bool_pattern`** — _a `count_bool_pattern` pattern._
  count = var.x ? 1 : 0 should be migrated to for_each

## Why it likely fired

count = var.x ? 1 : 0 should be migrated to for_each

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-COUNT-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `count = var.enabled ? 1 : 0` with:
```hcl
for_each = var.enabled ? toset(["this"]) : toset([])
```
The `for_each` approach produces map-keyed instances (`resource["this"]`)
instead of list-indexed ones (`resource[0]`). This eliminates fragile
`[0]` references, avoids off-by-one errors when the condition changes,
and makes `terraform plan` output clearer. The `one()` function can
simplify references: `one(resource.name[*].id)`.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
# Replace count = var.enabled ? 1 : 0 with for_each
resource "aws_security_group" "app" {
  for_each = var.enabled ? toset(["this"]) : toset([])
  name     = "app"
}

# Reference via one() to avoid [0] index
output "sg_id" {
  value = one(values(aws_security_group.app)[*].id)
}
```

## Verification

Grep for `count\s*=.*\?\s*1\s*:\s*0` in .tf files. Confirm all
conditional resources use for_each instead. Re-run tf-analyze and
confirm ROB-COUNT-001 is RESOLVED.

## References

**Source**
  - [`catalog/ROB-COUNT-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-COUNT-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-COUNT-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-COUNT-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-COUNT-001
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
