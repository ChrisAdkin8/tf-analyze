---
title: "ROB-COUNTREF-001 — Unguarded reference to count-conditional resource"
description: "tf-analyze rule ROB-COUNTREF-001 (MEDIUM · robustness): Unguarded reference to count-conditional resource"
keywords: "robustness, medium, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-COUNTREF-001 \u2014 Unguarded reference to count-conditional resource",
  "description": "Guard indexed references to count-conditional resources with a\nconditional expression or a try() wrapper:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-COUNTREF-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-COUNTREF-001/"
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

# 💡 ROB-COUNTREF-001 — Unguarded reference to count-conditional resource

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-COUNTREF-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Unguarded reference to count-conditional resource.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`count_index_ref`** — _a `count_index_ref` pattern._
  reference to resource[0] or module.X.output[0] where the source uses count and the consumer file has no matching conditional guard

## Why it likely fired

reference to resource[0] or module.X.output[0] where the source uses count and the consumer file has no matching conditional guard

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-COUNTREF-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Guard indexed references to count-conditional resources with a
conditional expression or a try() wrapper:

```hcl
# Instead of:
value = aws_instance.optional[0].id

# Use:
value = length(aws_instance.optional) > 0 ? aws_instance.optional[0].id : null
# Or:
value = try(aws_instance.optional[0].id, null)
```

Without the guard, destroying the conditional resource (count = 0)
produces an "index out of range" error.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
output "instance_id" {
  value = try(aws_instance.optional[0].id, null)
}

# Or with explicit length guard
output "instance_ip" {
  value = length(aws_instance.optional) > 0 ? aws_instance.optional[0].public_ip : null
}
```

## Verification

Set the count condition to false and run `terraform plan`. The plan
should succeed without index errors.

## References

**Source**
  - [`catalog/ROB-COUNTREF-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-COUNTREF-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-COUNTREF-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-COUNTREF-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-COUNTREF-001
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
