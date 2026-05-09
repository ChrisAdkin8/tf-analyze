---
title: "CI-TEST-001 — Module has no Terraform test files"
description: "tf-analyze rule CI-TEST-001 (LOW · cicd): Module has no Terraform test files"
keywords: "cicd, low, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "CI-TEST-001 \u2014 Module has no Terraform test files",
  "description": "Add at least one `.tftest.hcl` file covering the module's primary\nresource creation path. Terraform native tests (1.6+) validate both\nplan and apply without external tooling.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/CI-TEST-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/CI-TEST-001/"
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
  "keywords": "cicd, low, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "cicd",
  "isAccessibleForFree": true
}
</script>

# ℹ️ CI-TEST-001 — Module has no Terraform test files

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: cicd](https://img.shields.io/badge/section-cicd-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/CI-TEST-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Module has no Terraform test files.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`module_missing_tests`** — _a `module_missing_tests` pattern._
  module directory contains .tf files but no .tftest.hcl files (Terraform native test framework)

## Why it likely fired

module directory contains .tf files but no .tftest.hcl files (Terraform native test framework)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain CI-TEST-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add at least one `.tftest.hcl` file covering the module's primary
resource creation path. Terraform native tests (1.6+) validate both
plan and apply without external tooling.

Example:
```hcl
run "creates_bucket" {
  command = plan
  assert {
    condition     = google_storage_bucket.main.location == "US"
    error_message = "bucket location must be US"
  }
}
```

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Create a <module>.tftest.hcl file in the module directory
run "creates_resource" {
  command = plan

  assert {
    condition     = aws_s3_bucket.main.bucket != ""
    error_message = "bucket must be created with a non-empty name"
  }
}

run "apply_and_verify" {
  command = apply

  assert {
    condition     = aws_s3_bucket.main.region == "us-east-1"
    error_message = "bucket must be in us-east-1"
  }
}
```

## Verification

Run `terraform test` in the module directory.

## References

**Source**
  - [`catalog/CI-TEST-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/CI-TEST-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain CI-TEST-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore CI-TEST-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - CI-TEST-001
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
