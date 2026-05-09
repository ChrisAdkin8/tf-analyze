# ⚠️ STK-GCP-GKE-004 — GKE cluster missing master authorized networks

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **GKE cluster missing master authorized networks.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_container_cluster` (`master_authorized_networks_config.cidr_blocks`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-GKE-004` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `master_authorized_networks_config` block to restrict who can
reach the Kubernetes API server:

    master_authorized_networks_config {
      cidr_blocks {
        cidr_block   = "10.0.0.0/8"
        display_name = "internal-vpc"
      }
      cidr_blocks {
        cidr_block   = "<corporate-egress-cidr>"
        display_name = "corp-vpn"
      }
    }

Without this block the API server is reachable from any IP that can
reach GCP, making it a target for credential stuffing and zero-day
exploits against the Kubernetes API.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_container_cluster" "example" {
  name     = "example"
  location = "us-central1"
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "203.0.113.0/24"
      display_name = "corporate-vpn"
    }
  }
}
```

## Verification

```sh
`gcloud container clusters describe <name> \
  --format='value(masterAuthorizedNetworksConfig.cidrBlocks)'`
must return at least one CIDR entry.
```

## References

**CIS Benchmark**
  - `CIS 8.5.4`

**Source**
  - [`catalog/STK-GCP-GKE-004.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-GKE-004.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-GKE-004    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-GKE-004` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-GKE-004
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
