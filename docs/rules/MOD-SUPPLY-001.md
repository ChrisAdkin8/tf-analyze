---
title: "MOD-SUPPLY-001 — Module pinned to mutable git ref (main or master)"
description: "tf-analyze rule MOD-SUPPLY-001 (HIGH · module): Module pinned to mutable git ref (main or master)"
keywords: "module, high, terraform, iac, mitre-T1195.002"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "MOD-SUPPLY-001 \u2014 Module pinned to mutable git ref (main or master)",
  "description": "Replace `?ref=main` with a full commit SHA or semver tag:\n  source = \"git::https://github.com/org/module.git?ref=v1.2.3\"\nMutable refs can silently introduce breaking changes or malicious code\non the next `terraform init -upgrade`.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-SUPPLY-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-SUPPLY-001/"
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
  "keywords": "module, high, terraform, MITRE T1195.002",
  "proficiencyLevel": "Expert",
  "articleSection": "module",
  "isAccessibleForFree": true
}
</script>

# ⚠️ MOD-SUPPLY-001 — Module pinned to mutable git ref (main or master)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: module](https://img.shields.io/badge/section-module-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/MOD-SUPPLY-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Module pinned to mutable git ref (main or master).** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`grep`** matching `/source\s*=\s*"[^"]*\?ref=(main|master)"/` — _a textual regex matched somewhere in the file._
  Module source URL contains ?ref=main or ?ref=master

## Why it likely fired

Module source URL contains ?ref=main or ?ref=master

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain MOD-SUPPLY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `?ref=main` with a full commit SHA or semver tag:
  source = "git::https://github.com/org/module.git?ref=v1.2.3"
Mutable refs can silently introduce breaking changes or malicious code
on the next `terraform init -upgrade`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
module "example" {
  source = "git::https://github.com/example/module.git?ref=v1.2.3"
}
```

## Verification

Verify all git-sourced module URLs use a pinned tag or SHA, not main/master.

## References

**SOC 2 Trust Services Criteria**
  - `CC9.2`

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**Source**
  - [`catalog/MOD-SUPPLY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/MOD-SUPPLY-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain MOD-SUPPLY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore MOD-SUPPLY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - MOD-SUPPLY-001
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
