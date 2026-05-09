---
title: "OPS-ENV-001 — Prod-scoped resource lacks deletion_protection"
description: "tf-analyze rule OPS-ENV-001 (HIGH · ops): Prod-scoped resource lacks deletion_protection"
keywords: "ops, high, terraform, iac, cis-2.3"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "OPS-ENV-001 \u2014 Prod-scoped resource lacks deletion_protection",
  "description": "Production databases, GKE clusters, and storage buckets should be locked\nagainst accidental `terraform destroy`. Add `deletion_protection = true`\n(or `prevent_destroy = true` in a `lifecycle {}` block if the type doesn't\nexpose `deletion_pr",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/OPS-ENV-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/OPS-ENV-001/"
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
  "keywords": "ops, high, terraform, CIS 2.3",
  "proficiencyLevel": "Expert",
  "articleSection": "ops",
  "isAccessibleForFree": true
}
</script>

# ⚠️ OPS-ENV-001 — Prod-scoped resource lacks deletion_protection

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: ops](https://img.shields.io/badge/section-ops-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/OPS-ENV-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=OPS-ENV-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add OPS-ENV-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Prod-scoped resource lacks deletion_protection.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`prod_no_deletion_protection`** — _a `prod_no_deletion_protection` pattern._
  A resource in a prod path (or with environment=prod label) is missing deletion_protection=true on a type that supports it

## Why it likely fired

A resource in a prod path (or with environment=prod label) is missing deletion_protection=true on a type that supports it

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain OPS-ENV-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Production databases, GKE clusters, and storage buckets should be locked
against accidental `terraform destroy`. Add `deletion_protection = true`
(or `prevent_destroy = true` in a `lifecycle {}` block if the type doesn't
expose `deletion_protection`).

Scope of the check: path containing `prod`, or `labels = { environment =
"prod" }` on the resource. Dev/staging environments are excluded by design.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_db_instance" "example" {
  identifier        = "example-prod"
  deletion_protection = true
}
```

## Verification

Run `terraform plan` after the change and confirm only `+` additions
appear — the resource itself is not modified.

## References

**CIS Benchmark**
  - `CIS 2.3`

**Source**
  - [`catalog/OPS-ENV-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/OPS-ENV-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain OPS-ENV-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore OPS-ENV-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - OPS-ENV-001
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
