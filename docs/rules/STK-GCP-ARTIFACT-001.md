---
title: "STK-GCP-ARTIFACT-001 — Artifact Registry repository missing customer-managed encryption key"
description: "tf-analyze rule STK-GCP-ARTIFACT-001 (MEDIUM · stack): Artifact Registry repository missing customer-managed encryption key"
keywords: "stack, medium, terraform, iac, gcp, mitre-T1530, cwe-311, d3-ear"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-ARTIFACT-001 \u2014 Artifact Registry repository missing customer-managed encryption key",
  "description": "Add a `kms_key_name` pointing to a Cloud KMS CryptoKey:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-ARTIFACT-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-ARTIFACT-001/"
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
  "keywords": "stack, medium, terraform, MITRE T1530, CWE-311, D3-EAR",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-GCP-ARTIFACT-001 — Artifact Registry repository missing customer-managed encryption key

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-ARTIFACT-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-ARTIFACT-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-ARTIFACT-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Artifact Registry repository missing customer-managed encryption key.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_artifact_registry_repository` (`kms_key_name`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_artifact_registry_repository` has no `kms_key_name`
argument. Container images, language packages, and other artifacts
are encrypted with Google-managed keys only. For regulated workloads
(PCI-DSS, HIPAA, FedRAMP), a customer-managed key (CMEK) is required
so the organisation controls key rotation and can cryptographically
destroy all stored artifacts by disabling the key.

## Why it likely fired

`google_artifact_registry_repository` has no `kms_key_name`
argument. Container images, language packages, and other artifacts
are encrypted with Google-managed keys only. For regulated workloads
(PCI-DSS, HIPAA, FedRAMP), a customer-managed key (CMEK) is required
so the organisation controls key rotation and can cryptographically
destroy all stored artifacts by disabling the key.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-ARTIFACT-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `kms_key_name` pointing to a Cloud KMS CryptoKey:

    resource "google_artifact_registry_repository" "containers" {
      location      = "us-central1"
      repository_id = "containers"
      format        = "DOCKER"
      kms_key_name  = google_kms_crypto_key.artifact.id
    }

The KMS key ring must be in the same region as the repository.
Grant the Artifact Registry service account
`roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key before
creating the repository — otherwise `terraform apply` will fail
with a permission error.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_artifact_registry_repository" "example" {
  location      = "us-central1"
  repository_id = "example"
  format        = "DOCKER"
  kms_key_name  = google_kms_crypto_key.artifact.id
}
```

## Verification

```sh
`gcloud artifacts repositories describe <repo> --location=<region> \
  --format='value(encryptionConfig.kmsKeyName)'`
must return a non-empty KMS CryptoKey resource name.
```

## References

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**CWE**
  - [`CWE-311`](https://cwe.mitre.org/data/definitions/311.html)

**MITRE D3FEND**
  - [`D3-EAR`](https://d3fend.mitre.org/technique/D3-EAR/)

**Source**
  - [`catalog/STK-GCP-ARTIFACT-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-ARTIFACT-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-ARTIFACT-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-ARTIFACT-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-ARTIFACT-001
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
