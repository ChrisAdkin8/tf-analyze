---
title: "ROB-VERSION-002 — Submodule directory has no required_version"
description: "tf-analyze rule ROB-VERSION-002 (LOW · robustness): Submodule directory has no required_version"
keywords: "robustness, low, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-VERSION-002 \u2014 Submodule directory has no required_version",
  "description": "Submodules inherit the root's Terraform version *implicitly*. That hides\nfeature-level assumptions: a submodule using `optional()` object attrs or\n`moved {}` blocks will silently break if the root drops to pre-1.3 /\npre-1.1. Declare:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-VERSION-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-VERSION-002/"
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

# ℹ️ ROB-VERSION-002 — Submodule directory has no required_version

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-VERSION-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Submodule directory has no required_version.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`submodule_version_missing`** — _a `submodule_version_missing` pattern._
  A submodule directory (.tf present) has no required_version constraint anywhere

## Why it likely fired

A submodule directory (.tf present) has no required_version constraint anywhere

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-VERSION-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Submodules inherit the root's Terraform version *implicitly*. That hides
feature-level assumptions: a submodule using `optional()` object attrs or
`moved {}` blocks will silently break if the root drops to pre-1.3 /
pre-1.1. Declare:

```hcl
terraform {
  required_version = ">= 1.6"
}
```

in each submodule so `terraform get` fails fast on unsupported versions.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
terraform {
  required_version = ">= 1.6, < 2.0"
}
```

## Verification

Run `terraform init` inside the submodule directory (if it is callable
in isolation) — it should enforce the new constraint.

## References

**Source**
  - [`catalog/ROB-VERSION-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-VERSION-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-VERSION-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-VERSION-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-VERSION-002
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
