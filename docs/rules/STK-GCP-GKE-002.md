# ⚠️ STK-GCP-GKE-002 — GKE cluster missing Workload Identity

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **GKE cluster missing Workload Identity.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_container_cluster` (`workload_identity_config.workload_pool`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-GKE-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add to the cluster:

    workload_identity_config {
      workload_pool = "${var.project_id}.svc.id.goog"
    }

Without Workload Identity, pods that need GCP access must mount
static service account keys as Kubernetes secrets — a long-lived
credential that survives every pod restart and is hard to rotate.
WI binds a Kubernetes service account to a Google service account
via the cluster's identity pool, eliminating the static key.

Per-deployment, then bind a KSA to a GSA:

    resource "google_service_account_iam_member" "wi" {
      service_account_id = google_service_account.app.name
      role               = "roles/iam.workloadIdentityUser"
      member             = "serviceAccount:${var.project_id}.svc.id.goog[mynamespace/myksa]"
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_container_cluster" "example" {
  name     = "example"
  location = "us-central1"
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
}
```

## Verification

```sh
`gcloud container clusters describe <name> \\
   --format='value(workloadIdentityConfig.workloadPool)'`
must return `<project>.svc.id.goog`. Re-run tf-analyze; STK-GKE-002
should not fire.
```

## References

**CIS Benchmark**
  - `CIS 8.5.2`

**Related rules**
  - [`STK-GKE-NODEPOOL-001`](./STK-GKE-NODEPOOL-001.md)

**Source**
  - [`catalog/STK-GCP-GKE-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-GKE-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-GKE-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-GKE-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-GKE-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
