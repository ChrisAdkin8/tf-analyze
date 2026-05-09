---
title: "ROB-FOREACH-001 — for_each over list instead of map/set"
description: "tf-analyze rule ROB-FOREACH-001 (MEDIUM · robustness): for_each over list instead of map/set"
keywords: "robustness, medium, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-FOREACH-001 \u2014 for_each over list instead of map/set",
  "description": "`for_each` must iterate over a `map` or a `set`. Passing a list silently\nworks only because Terraform errors late \u2014 and when elements are removed\nor reordered, instances are destroyed and recreated because their keys are\nposition-dependent.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-FOREACH-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-FOREACH-001/"
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
  "keywords": "robustness, medium, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# 💡 ROB-FOREACH-001 — for_each over list instead of map/set

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-FOREACH-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **for_each over list instead of map/set.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`foreach_over_list`** — _a `foreach_over_list` pattern._
  for_each iterates over a list/tuple literal (not toset/map) — order-based keys, destructive on reorder

## Why it likely fired

for_each iterates over a list/tuple literal (not toset/map) — order-based keys, destructive on reorder

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-FOREACH-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

`for_each` must iterate over a `map` or a `set`. Passing a list silently
works only because Terraform errors late — and when elements are removed
or reordered, instances are destroyed and recreated because their keys are
position-dependent.

```hcl
for_each = toset(var.names)         # set (stable keys)
# or
for_each = { for n in var.names : n => {} }   # map with stable keys
```

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
# Before: for_each = ["alice", "bob"]  — list, order-sensitive
# After: wrap in toset() for stable keys
resource "aws_iam_user" "team" {
  for_each = toset(var.usernames)
  name     = each.key
}
```

## Verification

Run `terraform plan` after the change — if stable keys were already in use,
diff should be zero.

## References

**Source**
  - [`catalog/ROB-FOREACH-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-FOREACH-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-FOREACH-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-FOREACH-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-FOREACH-001
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
