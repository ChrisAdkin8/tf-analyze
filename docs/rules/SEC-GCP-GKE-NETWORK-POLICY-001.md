# ⚠️ SEC-GCP-GKE-NETWORK-POLICY-001 — GKE cluster missing network_policy enforcement

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **GKE cluster missing network_policy enforcement.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_container_cluster` (`network_policy`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-GKE-NETWORK-POLICY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Without `network_policy` on the cluster, every pod can reach every
other pod on every port — there is no namespace isolation, no
default-deny, and no way to enforce "frontend may talk to backend
but backend may not talk to internet" via Kubernetes
NetworkPolicies.

Enable it in Terraform:

    resource "google_container_cluster" "main" {
      # ...
      network_policy {
        enabled  = true
        provider = "CALICO"
      }

      addons_config {
        network_policy_config {
          disabled = false
        }
      }
    }

Then write `NetworkPolicy` Kubernetes manifests to allow only the
flows the workload needs. A sensible default is a namespace-scoped
deny-all egress with explicit allow rules for required services.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_container_cluster" "example" {
  name     = "example"
  location = "us-central1"
  network_policy {
    enabled  = true
    provider = "CALICO"
  }
  addons_config {
    network_policy_config { disabled = false }
  }
}
```

## Verification

After applying, run:

    gcloud container clusters describe <name> --location=<loc> \\
      --format='value(networkPolicy.enabled)'

Should print `True`. Then `kubectl get networkpolicies -A` should
show at least one default-deny policy in workload namespaces.

## References

**CIS Benchmark**
  - `CIS 6.6.7`

**Related rules**
  - [`STK-GKE-001`](./STK-GKE-001.md)

**Source**
  - [`catalog/SEC-GCP-GKE-NETWORK-POLICY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-GKE-NETWORK-POLICY-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-GKE-NETWORK-POLICY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-GKE-NETWORK-POLICY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-GKE-NETWORK-POLICY-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
