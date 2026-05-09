---
title: "STK-DEPRECATION-002 — Deprecated data source: data.template_file"
description: "tf-analyze rule STK-DEPRECATION-002 (MEDIUM · stack): Deprecated data source: data.template_file"
keywords: "stack, medium, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-DEPRECATION-002 \u2014 Deprecated data source: data.template_file",
  "description": "Replace with the built-in `templatefile()` function:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-DEPRECATION-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-DEPRECATION-002/"
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
  "keywords": "stack, medium, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-DEPRECATION-002 — Deprecated data source: data.template_file

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-DEPRECATION-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Deprecated data source: data.template_file.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`deprecated_datasource`** — _a `deprecated_datasource` pattern._
  data.template_file has been deprecated since Terraform 0.12 in favour of templatefile()

## Why it likely fired

data.template_file has been deprecated since Terraform 0.12 in favour of templatefile()

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-DEPRECATION-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace with the built-in `templatefile()` function:

```hcl
# Before
data "template_file" "init" {
  template = file("${path.module}/init.tpl")
  vars     = { name = var.name }
}

# After
locals {
  init = templatefile("${path.module}/init.tpl", { name = var.name })
}
```

`templatefile()` is evaluated at plan time natively — no provider
dependency, no resource graph node, and error messages point at the real
source line instead of a synthetic data-source.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
locals {
  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    environment = var.environment
  })
}
```

## Verification

Run `terraform plan` and confirm the rendered value is identical
(`diff <(terraform console <<< 'data.template_file.init.rendered')
<(terraform console <<< 'local.init')`).

## References

**Source**
  - [`catalog/STK-DEPRECATION-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-DEPRECATION-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-DEPRECATION-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-DEPRECATION-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-DEPRECATION-002
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
