---
title: "ROB-UNUSED-002 — Declared output is never consumed by any caller"
description: "tf-analyze rule ROB-UNUSED-002 (LOW · robustness): Declared output is never consumed by any caller"
keywords: "robustness, low, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-UNUSED-002 \u2014 Declared output is never consumed by any caller",
  "description": "Remove the unused output if no external consumer (CI scripts, other repos)\ndepends on it. Unused outputs clutter `terraform output` and may expose\nsensitive values unnecessarily.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-UNUSED-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-UNUSED-002/"
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

# ℹ️ ROB-UNUSED-002 — Declared output is never consumed by any caller

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-UNUSED-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-UNUSED-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-UNUSED-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Declared output is never consumed by any caller.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`output_unused`** — _a `output_unused` pattern._
  output declared in a child module but never referenced as module.X.output_name by any caller in the repo

## Why it likely fired

output declared in a child module but never referenced as module.X.output_name by any caller in the repo

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-UNUSED-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove the unused output if no external consumer (CI scripts, other repos)
depends on it. Unused outputs clutter `terraform output` and may expose
sensitive values unnecessarily.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Remove the unused output declaration entirely
# Before (delete this block):
# output "legacy_endpoint" {
#   value = aws_instance.app.public_ip
# }

# After: output is gone; verify no external CI scripts reference it
```

## Verification

Run `terraform validate` after removing the output. Search for any
external references (CI scripts, other repos) before deleting.

## References

**Source**
  - [`catalog/ROB-UNUSED-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-UNUSED-002.yaml) — canonical YAML

## Family

See also rules in the `ROB-UNUSED-*` family:

- [`ROB-UNUSED-001`](./ROB-UNUSED-001.md) — Declared variable is never referenced

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-UNUSED-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-UNUSED-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-UNUSED-002
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
