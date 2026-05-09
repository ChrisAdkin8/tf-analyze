---
title: "SEC-AWS-KINESIS-001 — Kinesis Data Stream not encrypted with KMS"
description: "tf-analyze rule SEC-AWS-KINESIS-001 (MEDIUM · security): Kinesis Data Stream not encrypted with KMS"
keywords: "security, medium, terraform, iac, aws, mitre-T1530"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-KINESIS-001 \u2014 Kinesis Data Stream not encrypted with KMS",
  "description": "Enable KMS encryption on every Kinesis stream:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-KINESIS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-KINESIS-001/"
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
  "keywords": "security, medium, terraform, MITRE T1530",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AWS-KINESIS-001 — Kinesis Data Stream not encrypted with KMS

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-KINESIS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Kinesis Data Stream not encrypted with KMS.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_kinesis_stream` (`encryption_type`) — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_kinesis_stream` has `encryption_type` absent or not set to `KMS`.
The default `NONE` encryption leaves stream data in plaintext at rest.
Anyone with access to the underlying storage can read records. Use
KMS encryption so that key-policy controls who can decrypt stream data.

## Why it likely fired

`aws_kinesis_stream` has `encryption_type` absent or not set to `KMS`.
The default `NONE` encryption leaves stream data in plaintext at rest.
Anyone with access to the underlying storage can read records. Use
KMS encryption so that key-policy controls who can decrypt stream data.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-KINESIS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable KMS encryption on every Kinesis stream:

    resource "aws_kinesis_stream" "main" {
      name             = "main"
      shard_count      = 1
      encryption_type  = "KMS"
      kms_key_id       = aws_kms_key.kinesis.id
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_kinesis_stream" "example" {
  name            = "example"
  shard_count     = 1
  encryption_type = "KMS"
  kms_key_id      = aws_kms_key.kinesis.id
}
```

## Verification

```sh
`aws kinesis describe-stream-summary --stream-name <name> \
  --query 'StreamDescriptionSummary.EncryptionType'`
must return `"KMS"`.
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**Source**
  - [`catalog/SEC-AWS-KINESIS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-KINESIS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-KINESIS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-KINESIS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-KINESIS-001
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
