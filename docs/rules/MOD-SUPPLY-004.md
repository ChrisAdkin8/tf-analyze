---
title: "MOD-SUPPLY-004 — Module version constraint uses `>=` with no upper bound"
description: "tf-analyze rule MOD-SUPPLY-004 (MEDIUM · module): Module version constraint uses `>=` with no upper bound"
keywords: "module, medium, terraform, iac, mitre-T1195.002, cwe-1357, cwe-1104"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "MOD-SUPPLY-004 \u2014 Module version constraint uses `>=` with no upper bound",
  "description": "version = \"~> 5.40\"            # caret-style, allows 5.x\n# OR\nversion = \">= 5.40, < 6.0\"     # explicit range\n# OR\nversion = \"= 5.42.1\"           # pinned (most defensive)",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-SUPPLY-004/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-SUPPLY-004/"
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
  "keywords": "module, medium, terraform, MITRE T1195.002, CWE-1357, CWE-1104",
  "proficiencyLevel": "Expert",
  "articleSection": "module",
  "isAccessibleForFree": true
}
</script>

# 💡 MOD-SUPPLY-004 — Module version constraint uses `>=` with no upper bound

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: module](https://img.shields.io/badge/section-module-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/MOD-SUPPLY-004" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=MOD-SUPPLY-004" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add MOD-SUPPLY-004 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Module version constraint uses `>=` with no upper bound.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`grep`** matching `/^\s*version\s*=\s*"\s*>=\s*[0-9]+\.[0-9]+/` — _a textual regex matched somewhere in the file._
  A version constraint of the shape `version = ">= 5.40"` (or
`version = ">= 5.40.0"`) has no upper bound — `terraform init`
pulls in any future major (6.x, 7.x). When a provider or module
ships a breaking change, this constraint promotes it without
review.

## Why it likely fired

A version constraint of the shape `version = ">= 5.40"` (or
`version = ">= 5.40.0"`) has no upper bound — `terraform init`
pulls in any future major (6.x, 7.x). When a provider or module
ships a breaking change, this constraint promotes it without
review.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain MOD-SUPPLY-004` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

version = "~> 5.40"            # caret-style, allows 5.x
# OR
version = ">= 5.40, < 6.0"     # explicit range
# OR
version = "= 5.42.1"           # pinned (most defensive)

OWASP CICD-SEC-3 (Dependency Chain Abuse) and SLSA L1 deps both
call out open upper bounds as the canonical
"ship a malicious patch on a Friday and it lands in every plan
the following Monday" pattern.

## Verification

```sh
`grep -rEn 'version\s*=\s*">=' --include="*.tf"`. Every match should
also include `<` to cap the upper bound.
```

## References

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1357`](https://cwe.mitre.org/data/definitions/1357.html)
  - [`CWE-1104`](https://cwe.mitre.org/data/definitions/1104.html)

**Source**
  - [`catalog/MOD-SUPPLY-004.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/MOD-SUPPLY-004.yaml) — canonical YAML

## Family

See also rules in the `MOD-SUPPLY-*` family:

- [`MOD-SUPPLY-001`](./MOD-SUPPLY-001.md) — Module pinned to mutable git ref (main or master)
- [`MOD-SUPPLY-002`](./MOD-SUPPLY-002.md) — Module uses raw git source instead of registry
- [`MOD-SUPPLY-003`](./MOD-SUPPLY-003.md) — Registry module missing version constraint

---

## Run this check

```sh
python3 scripts/detect.py --explain MOD-SUPPLY-004    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore MOD-SUPPLY-004` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - MOD-SUPPLY-004
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
