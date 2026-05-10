---
title: "STK-DEFAULTS-001 — Module lacks `terraform { required_version, required_providers }` block"
description: "tf-analyze rule STK-DEFAULTS-001 (MEDIUM · stack): Module lacks `terraform { required_version, required_providers }` block"
keywords: "stack, medium, terraform, iac, mitre-T1195.001, cwe-1357, cwe-1395"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-DEFAULTS-001 \u2014 Module lacks `terraform { required_version, required_providers }` block",
  "description": "# In versions.tf (one per module)\nterraform {\n  required_version = \">= 1.6.0\"\n  required_providers {\n    aws = {\n      source  = \"hashicorp/aws\"\n      version = \">= 5.40, < 6.0\"\n    }\n  }\n}",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-DEFAULTS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-DEFAULTS-001/"
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
  "keywords": "stack, medium, terraform, MITRE T1195.001, CWE-1357, CWE-1395",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-DEFAULTS-001 — Module lacks `terraform { required_version, required_providers }` block

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-DEFAULTS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-DEFAULTS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-DEFAULTS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Module lacks `terraform { required_version, required_providers }` block.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`submodule_version_missing`** — _a `submodule_version_missing` pattern._
  Module directory contains *.tf files but no top-level
`terraform { required_version = ">= ..." }` block. Without this
pin, `terraform init` falls back to "any installed version" —
which means consumers' Terraform major could be older than the
provider syntax this module uses, producing late-stage failures
on apply.

## Why it likely fired

Module directory contains *.tf files but no top-level
`terraform { required_version = ">= ..." }` block. Without this
pin, `terraform init` falls back to "any installed version" —
which means consumers' Terraform major could be older than the
provider syntax this module uses, producing late-stage failures
on apply.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-DEFAULTS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

# In versions.tf (one per module)
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40, < 6.0"
    }
  }
}

## Verification

```sh
`find . -name '*.tf' -execdir grep -l 'required_version' {} \; | sort -u`
should list every module root.
```

## References

**MITRE ATT&CK**
  - [`T1195.001`](https://attack.mitre.org/techniques/T1195/001/)

**CWE**
  - [`CWE-1357`](https://cwe.mitre.org/data/definitions/1357.html)
  - [`CWE-1395`](https://cwe.mitre.org/data/definitions/1395.html)

**Source**
  - [`catalog/STK-DEFAULTS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-DEFAULTS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-DEFAULTS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-DEFAULTS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-DEFAULTS-001
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
