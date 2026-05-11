---
title: "SEC-GCP-COMPUTE-SHIELDED-001 — GCP Compute instance missing shielded instance configuration"
description: "tf-analyze rule SEC-GCP-COMPUTE-SHIELDED-001 (MEDIUM · security): GCP Compute instance missing shielded instance configuration"
keywords: "security, medium, terraform, iac, gcp, mitre-T1542.003, cwe-1278, d3-psh, nist-csf-pr.pt-3, nist-800-53-si-7, csa-ccm-ivs-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-COMPUTE-SHIELDED-001 \u2014 GCP Compute instance missing shielded instance configuration",
  "description": "Add a `shielded_instance_config` block to every `google_compute_instance`:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-COMPUTE-SHIELDED-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-COMPUTE-SHIELDED-001/"
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
  "keywords": "security, medium, terraform, MITRE T1542.003, CWE-1278, D3-PSH",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-GCP-COMPUTE-SHIELDED-001 — GCP Compute instance missing shielded instance configuration

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-COMPUTE-SHIELDED-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-COMPUTE-SHIELDED-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-COMPUTE-SHIELDED-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Compute instance missing shielded instance configuration.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_compute_instance` (`shielded_instance_config.enable_secure_boot`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_compute_instance` without a `shielded_instance_config` block.
Shielded VMs provide Secure Boot, vTPM, and integrity monitoring — the
three controls that prevent a compromised bootloader or kernel module
from persisting across reboots undetected.

## Why it likely fired

`google_compute_instance` without a `shielded_instance_config` block.
Shielded VMs provide Secure Boot, vTPM, and integrity monitoring — the
three controls that prevent a compromised bootloader or kernel module
from persisting across reboots undetected.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-COMPUTE-SHIELDED-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `shielded_instance_config` block to every `google_compute_instance`:

    resource "google_compute_instance" "app" {
      # ...
      shielded_instance_config {
        enable_secure_boot          = true
        enable_vtpm                 = true
        enable_integrity_monitoring = true
      }
    }

The machine must use a Shielded-compatible image (all standard GCP images
published after 2018 are shielded-compatible). Use
`gcloud compute images list --filter="shielded=true"` to confirm.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_compute_instance" "example" {
  name         = "example"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  boot_disk {
    initialize_params { image = "debian-cloud/debian-11" }
  }
  network_interface { network = "default" }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}
```

## Verification

```sh
`gcloud compute instances describe <instance> --format="json(shieldedInstanceConfig)"`
must show `enableSecureBoot: true`. Re-run tf-analyze in mode:verify-fixed.
```

## References

**MITRE ATT&CK**
  - [`T1542.003`](https://attack.mitre.org/techniques/T1542/003/)

**CWE**
  - [`CWE-1278`](https://cwe.mitre.org/data/definitions/1278.html)

**MITRE D3FEND**
  - [`D3-PSH`](https://d3fend.mitre.org/technique/D3-PSH/)

**NIST CSF 2.0**
  - [`PR.PT-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SI-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=si-7)

**CSA CCM v4**
  - [`IVS-03`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Related rules**
  - [`STK-GCP-GKE-NODEPOOL-001`](./STK-GCP-GKE-NODEPOOL-001.md)

**Source**
  - [`catalog/SEC-GCP-COMPUTE-SHIELDED-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-COMPUTE-SHIELDED-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-COMPUTE-SHIELDED-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-COMPUTE-SHIELDED-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-COMPUTE-SHIELDED-001
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
