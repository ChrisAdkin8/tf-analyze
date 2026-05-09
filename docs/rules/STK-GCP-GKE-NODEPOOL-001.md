# ⚠️ STK-GCP-GKE-NODEPOOL-001 — GKE node pool missing shielded-instance hardening

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **GKE node pool missing shielded-instance hardening.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`graph_check`** — _a corpus-wide graph check fired (cross-resource invariant)._
  Every `google_container_node_pool` attached to a cluster must set
`node_config.shielded_instance_config.enable_secure_boot = true` AND
`enable_integrity_monitoring = true`. Pods schedule across pools, so
one unhardened pool nullifies the cluster-wide posture.

## Why it likely fired

Every `google_container_node_pool` attached to a cluster must set
`node_config.shielded_instance_config.enable_secure_boot = true` AND
`enable_integrity_monitoring = true`. Pods schedule across pools, so
one unhardened pool nullifies the cluster-wide posture.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-GKE-NODEPOOL-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add to each `google_container_node_pool`:

    node_config {
      shielded_instance_config {
        enable_secure_boot          = true
        enable_integrity_monitoring = true
      }
    }

Then re-create the pool — `node_config` changes force replacement, so
schedule the cycle during a maintenance window or use surge upgrades.

Tip: enforce this at cluster level via Org Policy
`constraints/container.requireShieldedNodes`. The Terraform finding then
becomes a defense-in-depth check rather than the only line of defense.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_container_node_pool" "example" {
  name       = "example"
  cluster    = google_container_cluster.example.id
  location   = "us-central1"
  node_config {
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }
}
```

## Verification

After applying, run:

    gcloud container node-pools describe <pool> \\
      --cluster=<cluster> --region=<region> \\
      --format='value(config.shieldedInstanceConfig.enableSecureBoot,config.shieldedInstanceConfig.enableIntegrityMonitoring)'

Both fields should print `True`. Re-run tf-analyze to confirm clean.

## References

**CIS Benchmark**
  - `CIS 6.5.5`

**Related rules**
  - [`SEC-IAM-001`](./SEC-IAM-001.md)

**Source**
  - [`catalog/STK-GCP-GKE-NODEPOOL-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-GKE-NODEPOOL-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-GKE-NODEPOOL-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-GKE-NODEPOOL-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-GKE-NODEPOOL-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
