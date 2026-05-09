# ⚠️ SEC-GCP-COMPUTE-SA-001 — Compute instance uses default Compute Engine service account

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Compute instance uses default Compute Engine service account.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_compute_instance` (`service_account`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-COMPUTE-SA-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

When `service_account` is omitted, the VM runs as the project's
default Compute Engine SA (`<project-number>-compute@developer.
gserviceaccount.com`), which holds `roles/editor` project-wide. Any
workload code running on the VM inherits that level of access — far
too broad for almost any application.

Create a dedicated SA scoped to the workload and bind it explicitly:

    resource "google_service_account" "vm_runtime" {
      account_id   = "vm-runtime"
      display_name = "Runtime SA for ${var.app_name}"
    }

    resource "google_compute_instance" "app" {
      # ...
      service_account {
        email  = google_service_account.vm_runtime.email
        scopes = ["cloud-platform"]
      }
    }

Then attach narrow IAM grants to that SA on only the resources the
workload needs (objectViewer on a specific bucket, etc.).

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_service_account" "vm" {
  account_id = "vm-runtime"
}
resource "google_compute_instance" "example" {
  name         = "example"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  boot_disk {
    initialize_params { image = "debian-cloud/debian-11" }
  }
  network_interface { network = "default" }
  service_account {
    email  = google_service_account.vm.email
    scopes = ["cloud-platform"]
  }
}
```

## Verification

After applying, confirm with:

    gcloud compute instances describe <name> --zone=<zone> \\
      --format='value(serviceAccounts[0].email)'

The output should not match `<project-number>-compute@developer
.gserviceaccount.com`.

## References

**CIS Benchmark**
  - `CIS 4.1`

**Related rules**
  - [`SEC-IAM-001`](./SEC-IAM-001.md)

**Source**
  - [`catalog/SEC-GCP-COMPUTE-SA-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-COMPUTE-SA-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-COMPUTE-SA-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-COMPUTE-SA-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-COMPUTE-SA-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
