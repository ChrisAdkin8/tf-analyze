---
title: "ROB-UNUSED-001 — Declared variable is never referenced"
description: "tf-analyze rule ROB-UNUSED-001 (LOW · robustness): Declared variable is never referenced"
keywords: "robustness, low, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-UNUSED-001 \u2014 Declared variable is never referenced",
  "description": "Remove the unused variable declaration. Unused variables create confusion\nfor module consumers who set them expecting an effect. If the variable was\nintentionally reserved for future use, add a comment explaining why.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-UNUSED-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-UNUSED-001/"
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

# ℹ️ ROB-UNUSED-001 — Declared variable is never referenced

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-UNUSED-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Declared variable is never referenced.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`variable_unused`** — _a `variable_unused` pattern._
  variable declared in variables.tf but never referenced as var.X in any .tf file in the same module directory

## Why it likely fired

variable declared in variables.tf but never referenced as var.X in any .tf file in the same module directory

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-UNUSED-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove the unused variable declaration. Unused variables create confusion
for module consumers who set them expecting an effect. If the variable was
intentionally reserved for future use, add a comment explaining why.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Remove the unused variable declaration entirely
# Before (delete this block):
# variable "deprecated_flag" {
#   type    = bool
#   default = false
# }

# After: variable is gone; no .tfvars assignment needed
```

## Verification

Run `terraform validate` after removing the variable. If any .tfvars file
sets it, remove that assignment too.

## References

**Source**
  - [`catalog/ROB-UNUSED-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-UNUSED-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-UNUSED-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-UNUSED-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-UNUSED-001
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
