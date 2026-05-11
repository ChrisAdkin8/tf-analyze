---
title: "STK-GCP-GKE-003 — GKE cluster missing application-layer secrets encryption"
description: "tf-analyze rule STK-GCP-GKE-003 (HIGH · stack): GKE cluster missing application-layer secrets encryption"
keywords: "stack, high, terraform, iac, gcp, cis-8.5.5, mitre-T1552.001, cwe-522, nist-csf-pr.ac-1"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-GKE-003 \u2014 GKE cluster missing application-layer secrets encryption",
  "description": "Add a `database_encryption { state = \"ENCRYPTED\" key_name = <kms-key> }`\nblock. Without this, etcd-stored Kubernetes Secrets are encrypted only\nat the Google-managed disk level \u2014 not at the application layer.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-GKE-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-GKE-003/"
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
  "keywords": "stack, high, terraform, CIS 8.5.5, MITRE T1552.001, CWE-522",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-GCP-GKE-003 — GKE cluster missing application-layer secrets encryption

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-GKE-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-GKE-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-GKE-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GKE cluster missing application-layer secrets encryption.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_container_cluster` (`database_encryption.state`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-GKE-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `database_encryption { state = "ENCRYPTED" key_name = <kms-key> }`
block. Without this, etcd-stored Kubernetes Secrets are encrypted only
at the Google-managed disk level — not at the application layer.

    database_encryption {
      state    = "ENCRYPTED"
      key_name = google_kms_crypto_key.k8s_secrets.id
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_container_cluster" "example" {
  name     = "example"
  location = "us-central1"
  database_encryption {
    state    = "ENCRYPTED"
    key_name = google_kms_crypto_key.gke.id
  }
}
```

## Verification

```sh
`gcloud container clusters describe <name> --format='value(databaseEncryption.state)'`
must return `ENCRYPTED`.
```

## References

**CIS Benchmark**
  - `CIS 8.5.5`

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)

**CWE**
  - [`CWE-522`](https://cwe.mitre.org/data/definitions/522.html)

**NIST CSF 2.0**
  - [`PR.AC-1`](https://www.nist.gov/cyberframework)

**Source**
  - [`catalog/STK-GCP-GKE-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-GKE-003.yaml) — canonical YAML

## Family

See also rules in the `STK-GCP-GKE-*` family:

- [`STK-GCP-GKE-001`](./STK-GCP-GKE-001.md) — GKE cluster missing private nodes
- [`STK-GCP-GKE-002`](./STK-GCP-GKE-002.md) — GKE cluster missing Workload Identity
- [`STK-GCP-GKE-004`](./STK-GCP-GKE-004.md) — GKE cluster missing master authorized networks

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-GKE-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-GKE-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-GKE-003
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
