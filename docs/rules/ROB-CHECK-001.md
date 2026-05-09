---
title: "ROB-CHECK-001 — TF 1.5+ check block missing assert"
description: "tf-analyze rule ROB-CHECK-001 (MEDIUM · robustness): TF 1.5+ check block missing assert"
keywords: "robustness, medium, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-CHECK-001 \u2014 TF 1.5+ check block missing assert",
  "description": "Either delete the block, or add at least one `assert` body:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-CHECK-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-CHECK-001/"
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
  "keywords": "robustness, medium, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# 💡 ROB-CHECK-001 — TF 1.5+ check block missing assert

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-CHECK-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **TF 1.5+ check block missing assert.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`check_block_missing_assert`** — _a `check_block_missing_assert` pattern._
  A `check "name" {}` block contains no `assert {}` body. Terraform
treats this as valid HCL and silently runs the block as a no-op
on every plan/apply — the most common failure mode is an
assertion author left a stub block when they intended to write a
condition and never came back to it.

## Why it likely fired

A `check "name" {}` block contains no `assert {}` body. Terraform
treats this as valid HCL and silently runs the block as a no-op
on every plan/apply — the most common failure mode is an
assertion author left a stub block when they intended to write a
condition and never came back to it.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-CHECK-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Either delete the block, or add at least one `assert` body:

    check "instance_count_matches_quota" {
      data "google_compute_project_quota" "instances" { ... }

      assert {
        condition     = data.google_compute_project_quota.instances.usage <
                        data.google_compute_project_quota.instances.limit
        error_message = "Compute instance quota nearly exhausted."
      }
    }

Empty checks should be removed from version control rather than
retained as documentation — comments are a better fit for that.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
check "health_check" {
  data "http" "example" {
    url = "https://${aws_lb.example.dns_name}/health"
  }
  assert {
    condition     = data.http.example.status_code == 200
    error_message = "Health endpoint returned ${data.http.example.status_code}, expected 200"
  }
}
```

## Verification

After applying the fix, `terraform validate` should still pass and
`terraform plan` shows the assert running. Re-run tf-analyze;
ROB-CHECK-001 should not fire.

## References

**Related rules**
  - [`ROB-VALIDATION-001`](./ROB-VALIDATION-001.md)
  - [`ROB-PRECONDITION-001`](./ROB-PRECONDITION-001.md)

**Source**
  - [`catalog/ROB-CHECK-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-CHECK-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-CHECK-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-CHECK-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-CHECK-001
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
