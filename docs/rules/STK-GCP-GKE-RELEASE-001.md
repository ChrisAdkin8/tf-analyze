---
title: "STK-GCP-GKE-RELEASE-001 — GKE cluster on STATIC release channel (no auto-upgrade)"
description: "tf-analyze rule STK-GCP-GKE-RELEASE-001 (MEDIUM · stack): GKE cluster on STATIC release channel (no auto-upgrade)"
keywords: "stack, medium, terraform, iac, gcp, mitre-T1195.002, cwe-1104, d3-sca, nist-csf-id.sc-2, nist-800-53-sr-4, slsa-deps"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-GKE-RELEASE-001 \u2014 GKE cluster on STATIC release channel (no auto-upgrade)",
  "description": "Enroll the cluster on a managed release channel (RAPID, REGULAR, or\nSTABLE) so the control plane and node pools receive automatic\nupgrades within the channel's cadence:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-GKE-RELEASE-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-GKE-RELEASE-001/"
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
  "keywords": "stack, medium, terraform, MITRE T1195.002, CWE-1104, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-GCP-GKE-RELEASE-001 — GKE cluster on STATIC release channel (no auto-upgrade)

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-GKE-RELEASE-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-GKE-RELEASE-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-GKE-RELEASE-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GKE cluster on STATIC release channel (no auto-upgrade).** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`resource_body_contains`** on `google_container_cluster` matching `/release_channel\s*\{[^}]*channel\s*=\s*"UNSPECIFIED"/` — _the resource body matches a regex inside the block._
  `google_container_cluster.release_channel.channel = "UNSPECIFIED"`
pins the cluster to the static (no-channel) release stream, which
disables auto-upgrade. The control plane drifts onto unsupported
versions and accumulates CVEs.

## Why it likely fired

`google_container_cluster.release_channel.channel = "UNSPECIFIED"`
pins the cluster to the static (no-channel) release stream, which
disables auto-upgrade. The control plane drifts onto unsupported
versions and accumulates CVEs.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-GKE-RELEASE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enroll the cluster on a managed release channel (RAPID, REGULAR, or
STABLE) so the control plane and node pools receive automatic
upgrades within the channel's cadence:

    resource "google_container_cluster" "main" {
      # ...
      release_channel {
        channel = "REGULAR"
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_container_cluster" "example" {
  name               = "example"
  location           = "us-central1"
  initial_node_count = 1
  release_channel {
    channel = "REGULAR"
  }
}
```

## Verification

```sh
`gcloud container clusters describe <name> --format='value(releaseChannel.channel)'`
must return `RAPID`, `REGULAR`, or `STABLE` (not `UNSPECIFIED`).
```

## References

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1104`](https://cwe.mitre.org/data/definitions/1104.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**NIST CSF 2.0**
  - [`ID.SC-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SR-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-4)

**SLSA v1.0**
  - [`SLSA deps`](https://slsa.dev/spec/v1.0/deps-track)

**Source**
  - [`catalog/STK-GCP-GKE-RELEASE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-GKE-RELEASE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-GKE-RELEASE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-GKE-RELEASE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-GKE-RELEASE-001
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
