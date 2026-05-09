# 💡 SEC-GCP-COMPUTE-SHIELDED-001 — GCP Compute instance missing shielded instance configuration

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

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

[← Index of all rules](./)
