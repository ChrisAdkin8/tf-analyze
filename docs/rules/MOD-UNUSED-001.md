---
title: "MOD-UNUSED-001 — Local module directory is not called from any scenario"
description: "tf-analyze rule MOD-UNUSED-001 (LOW · module): Local module directory is not called from any scenario"
keywords: "module, low, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "MOD-UNUSED-001 \u2014 Local module directory is not called from any scenario",
  "description": "Three options, in order of preference:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-UNUSED-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-UNUSED-001/"
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
  "keywords": "module, low, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "module",
  "isAccessibleForFree": true
}
</script>

# ℹ️ MOD-UNUSED-001 — Local module directory is not called from any scenario

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: module](https://img.shields.io/badge/section-module-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/MOD-UNUSED-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=MOD-UNUSED-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add MOD-UNUSED-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Local module directory is not called from any scenario.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`module_unused`** — _a `module_unused` pattern._
  A directory in this repository declares Terraform variables and
outputs (the reusability contract that defines a module), but no
`module { source = "<relpath>" }` block in the scanned corpus
references it. Either the module is dead code that should be
deleted, or it's intentionally consumed from outside the scan
target — in which case the suppression should be documented.

## Why it likely fired

A directory in this repository declares Terraform variables and
outputs (the reusability contract that defines a module), but no
`module { source = "<relpath>" }` block in the scanned corpus
references it. Either the module is dead code that should be
deleted, or it's intentionally consumed from outside the scan
target — in which case the suppression should be documented.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain MOD-UNUSED-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Three options, in order of preference:

1. **Delete it** if the module is genuinely dead. Branches and tags
   preserve the history; keeping orphan modules around just costs
   reviewers' time.
2. **Add a caller** in a scenario directory if the module is
   supposed to be wired up but isn't yet — common after a refactor
   that lifted code into a module without finishing the swap.
3. **Document the external consumer** with a top-of-file comment
   and suppress the rule via `.tf-analyze.yaml`'s `ignore_rules:`
   when the module is published as a public registry artefact or
   consumed from a sibling repo not in the scan target.

This rule fires conservatively: it only flags directories that
declare both `variable {}` and/or `output {}` blocks. Raw resource
collections without an input/output contract aren't classified as
modules and won't fire here.

## Verification

Confirm with `grep -r 'source\s*=\s*"\(\\./\|\\.\\./\)' .` whether
any `.tf` file outside the orphan directory's parent references it.
If the grep is silent, the rule is right and the module is orphaned.

## References

**Related rules**
  - [`ROB-UNUSED-001`](./ROB-UNUSED-001.md)
  - [`ROB-UNUSED-002`](./ROB-UNUSED-002.md)

**Source**
  - [`catalog/MOD-UNUSED-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/MOD-UNUSED-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain MOD-UNUSED-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore MOD-UNUSED-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - MOD-UNUSED-001
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
