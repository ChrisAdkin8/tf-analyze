---
title: "ROB-PRECONDITION-001 — Precondition or postcondition missing error_message"
description: "tf-analyze rule ROB-PRECONDITION-001 (MEDIUM · robustness): Precondition or postcondition missing error_message"
keywords: "robustness, medium, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-PRECONDITION-001 \u2014 Precondition or postcondition missing error_message",
  "description": "Add a descriptive `error_message`:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-PRECONDITION-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-PRECONDITION-001/"
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

# 💡 ROB-PRECONDITION-001 — Precondition or postcondition missing error_message

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-PRECONDITION-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-PRECONDITION-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-PRECONDITION-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Precondition or postcondition missing error_message.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`precondition_missing_error_message`** — _a `precondition_missing_error_message` pattern._
  A `precondition` or `postcondition` block lacks `error_message`.
When the assertion fails Terraform emits a generic "Module output
precondition failed." with the source line as the only context —
operators on call have to grep the file to figure out what went
wrong.

## Why it likely fired

A `precondition` or `postcondition` block lacks `error_message`.
When the assertion fails Terraform emits a generic "Module output
precondition failed." with the source line as the only context —
operators on call have to grep the file to figure out what went
wrong.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-PRECONDITION-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a descriptive `error_message`:

    precondition {
      condition     = var.environment != "prod" || var.deletion_protection
      error_message = "Production resources must enable deletion_protection."
    }

The message should name the variable / invariant being protected
and what the operator should change. Keep it under 200 chars so
Terraform doesn't truncate in CLI output.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_instance" "example" {
  ami           = var.ami_id
  instance_type = var.instance_type
  lifecycle {
    precondition {
      condition     = can(regex("^ami-", var.ami_id))
      error_message = "ami_id must start with 'ami-' (got: ${var.ami_id})"
    }
  }
}
```

## Verification

Trigger the precondition (e.g. by setting variables that would fail
the assertion) and confirm the error message appears verbatim in
`terraform plan` output. Re-run tf-analyze; the rule should not fire.

## References

**Related rules**
  - [`ROB-VALIDATION-001`](./ROB-VALIDATION-001.md)
  - [`ROB-CHECK-001`](./ROB-CHECK-001.md)

**Source**
  - [`catalog/ROB-PRECONDITION-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-PRECONDITION-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-PRECONDITION-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-PRECONDITION-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-PRECONDITION-001
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
