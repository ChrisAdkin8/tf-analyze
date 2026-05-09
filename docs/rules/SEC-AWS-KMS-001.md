---
title: "SEC-AWS-KMS-001 — KMS key rotation disabled"
description: "tf-analyze rule SEC-AWS-KMS-001 (HIGH · security): KMS key rotation disabled"
keywords: "security, high, terraform, iac, aws, cis-3.8"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-KMS-001 \u2014 KMS key rotation disabled",
  "description": "Add `enable_key_rotation = true` to every `aws_kms_key`. AWS automatically\nrotates the key material once a year when rotation is enabled; the old\nbacking key material is retained to decrypt data encrypted before the\nrotation. Disabling rota",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-KMS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-KMS-001/"
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
  "keywords": "security, high, terraform, CIS 3.8",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-KMS-001 — KMS key rotation disabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-KMS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-KMS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-KMS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **KMS key rotation disabled.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_arg`** on `aws_kms_key` (`enable_key_rotation`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  KMS key with enable_key_rotation = false
2. **`resource_missing_arg`** on `aws_kms_key` (`enable_key_rotation`) — _the resource is missing a required attribute (or nested attribute path)._
  KMS key missing enable_key_rotation (defaults to false)

## Why it likely fired

KMS key with enable_key_rotation = false

KMS key missing enable_key_rotation (defaults to false)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-KMS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `enable_key_rotation = true` to every `aws_kms_key`. AWS automatically
rotates the key material once a year when rotation is enabled; the old
backing key material is retained to decrypt data encrypted before the
rotation. Disabling rotation means that a compromised key remains in use
indefinitely, violating least-privilege and common compliance controls
(CIS AWS 2.8, PCI-DSS Requirement 3.6.4).

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_kms_key" "example" {
  description         = "..."
  enable_key_rotation = true
}
```

_Enabling key rotation does not replace the key; existing ciphertext remains decryptable. Requires a terraform plan/apply cycle._

## Verification

Run `aws kms get-key-rotation-status --key-id <id>` and confirm
`KeyRotationEnabled` is `true`. Run `terraform plan` and verify no diff
shows `enable_key_rotation = false`.

## References

**CIS Benchmark**
  - `CIS 3.8`

**PCI-DSS**
  - `Req-3.6`

**Source**
  - [`catalog/SEC-AWS-KMS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-KMS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-KMS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-KMS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-KMS-001
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
