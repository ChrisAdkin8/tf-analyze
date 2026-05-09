---
title: "ROB-VERSION-003 — required_providers entry missing version constraint"
description: "tf-analyze rule ROB-VERSION-003 (HIGH · robustness): required_providers entry missing version constraint"
keywords: "robustness, high, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-VERSION-003 \u2014 required_providers entry missing version constraint",
  "description": "Add a `version` constraint to every provider entry in `required_providers`:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-VERSION-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-VERSION-003/"
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
  "keywords": "robustness, high, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# ⚠️ ROB-VERSION-003 — required_providers entry missing version constraint

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-VERSION-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-VERSION-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-VERSION-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **required_providers entry missing version constraint.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`providers_version_missing`** — _a `providers_version_missing` pattern._
  A `terraform { required_providers { ... } }` block contains a provider
entry without a `version` constraint. Without pinning, `terraform init`
may pull a newer major version that introduces breaking changes or new
provider defaults (e.g., a security-relevant default changing from
`false` to `true` or vice versa).

## Why it likely fired

A `terraform { required_providers { ... } }` block contains a provider
entry without a `version` constraint. Without pinning, `terraform init`
may pull a newer major version that introduces breaking changes or new
provider defaults (e.g., a security-relevant default changing from
`false` to `true` or vice versa).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-VERSION-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `version` constraint to every provider entry in `required_providers`:

    terraform {
      required_providers {
        google = {
          source  = "hashicorp/google"
          version = "~> 5.0"
        }
        aws = {
          source  = "hashicorp/aws"
          version = "~> 5.0"
        }
      }
    }

The `~> X.Y` pessimistic-constraint operator pins the major version while
allowing minor/patch updates. For production environments, consider exact
pinning (`= X.Y.Z`) and committing `.terraform.lock.hcl`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
terraform {
  required_version = ">= 1.5.0, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}
```

## Verification

Run `terraform init -upgrade` and confirm no provider is downloaded at
an unexpected version. The `.terraform.lock.hcl` file should exist and
be committed to version control.

## References

**Related rules**
  - [`ROB-VERSION-001`](./ROB-VERSION-001.md)
  - [`ROB-VERSION-002`](./ROB-VERSION-002.md)

**Source**
  - [`catalog/ROB-VERSION-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-VERSION-003.yaml) — canonical YAML

## Family

See also rules in the `ROB-VERSION-*` family:

- [`ROB-VERSION-001`](./ROB-VERSION-001.md) — required_version floor too old for skill assumptions
- [`ROB-VERSION-002`](./ROB-VERSION-002.md) — Submodule directory has no required_version

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-VERSION-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-VERSION-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-VERSION-003
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
