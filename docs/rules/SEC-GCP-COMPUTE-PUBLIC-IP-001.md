# ⚠️ SEC-GCP-COMPUTE-PUBLIC-IP-001 — Compute instance has a public IP via access_config

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Compute instance has a public IP via access_config.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_body_contains`** on `google_compute_instance` matching `/access_config\s*\{/` — _the resource body matches a regex inside the block._
  A `google_compute_instance` body contains an `access_config {}`
sub-block (always inside `network_interface`). Even an empty
`access_config` block requests an ephemeral public IP, exposing
the VM directly to the internet.

## Why it likely fired

A `google_compute_instance` body contains an `access_config {}`
sub-block (always inside `network_interface`). Even an empty
`access_config` block requests an ephemeral public IP, exposing
the VM directly to the internet.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-COMPUTE-PUBLIC-IP-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove the `access_config {}` block:

    network_interface {
      network    = google_compute_network.app.id
      subnetwork = google_compute_subnetwork.app.id
      # No access_config => no public IP
    }

If outbound internet access is needed for package fetches or API
calls, use a Cloud NAT gateway on the VPC. If inbound access is
needed (rare), put the VM behind an Identity-Aware Proxy or HTTPS
load balancer rather than exposing the instance directly.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_compute_instance" "example" {
  name         = "example"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  boot_disk {
    initialize_params { image = "debian-cloud/debian-11" }
  }
  network_interface {
    network    = google_compute_network.vpc.id
    subnetwork = google_compute_subnetwork.private.id
    # No access_config block — no public IP assigned
  }
}
```

## Verification

After applying, run:

    gcloud compute instances describe <name> --zone=<zone> \\
      --format='value(networkInterfaces[0].accessConfigs)'

This should print nothing. Re-run tf-analyze to confirm clean.

## References

**CIS Benchmark**
  - `CIS 4.9`

**Related rules**
  - [`SEC-NETWORK-001`](./SEC-NETWORK-001.md)

**Source**
  - [`catalog/SEC-GCP-COMPUTE-PUBLIC-IP-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-COMPUTE-PUBLIC-IP-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-COMPUTE-PUBLIC-IP-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-COMPUTE-PUBLIC-IP-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-COMPUTE-PUBLIC-IP-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
