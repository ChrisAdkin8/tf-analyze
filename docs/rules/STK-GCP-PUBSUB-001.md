---
title: "STK-GCP-PUBSUB-001 — Pub/Sub topic missing customer-managed encryption key"
description: "tf-analyze rule STK-GCP-PUBSUB-001 (MEDIUM · stack): Pub/Sub topic missing customer-managed encryption key"
keywords: "stack, medium, terraform, iac, gcp"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-PUBSUB-001 \u2014 Pub/Sub topic missing customer-managed encryption key",
  "description": "Bind a Cloud KMS key to the topic:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-PUBSUB-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-PUBSUB-001/"
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
  "keywords": "stack, medium, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-GCP-PUBSUB-001 — Pub/Sub topic missing customer-managed encryption key

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-PUBSUB-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-PUBSUB-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-PUBSUB-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Pub/Sub topic missing customer-managed encryption key.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_pubsub_topic` (`kms_key_name`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_pubsub_topic` without `kms_key_name`. Messages stored in
the topic buffer — including any PII, credentials, or structured
data that producers push — are encrypted with Google-managed keys.
A CMEK binding ensures the organisation controls key rotation,
holds evidence of access, and can revoke access to the data by
disabling the key.

## Why it likely fired

`google_pubsub_topic` without `kms_key_name`. Messages stored in
the topic buffer — including any PII, credentials, or structured
data that producers push — are encrypted with Google-managed keys.
A CMEK binding ensures the organisation controls key rotation,
holds evidence of access, and can revoke access to the data by
disabling the key.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-PUBSUB-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Bind a Cloud KMS key to the topic:

    resource "google_pubsub_topic" "app" {
      name       = "app-events"
      kms_key_name = google_kms_crypto_key.pubsub.id
    }

    resource "google_kms_crypto_key_iam_member" "pubsub" {
      crypto_key_id = google_kms_crypto_key.pubsub.id
      role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
      member        = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
    }

The Pub/Sub service agent must have `cloudkms.cryptoKeyEncrypterDecrypter`
on the key — without the IAM binding the topic will fail to publish.

For topics in a regulated environment (HIPAA, FedRAMP), pair the CMEK
with `google_kms_crypto_key.rotation_period` of ≤ 90 days to satisfy
CIS GCP 1.10.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_pubsub_topic" "example" {
  name         = "example"
  kms_key_name = google_kms_crypto_key.pubsub.id
}
```

## Verification

```sh
`gcloud pubsub topics describe <topic> --format='value(kmsKeyName)'`
must return the full key resource ID.
```

## References

**Source**
  - [`catalog/STK-GCP-PUBSUB-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-PUBSUB-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-PUBSUB-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-PUBSUB-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-PUBSUB-001
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
