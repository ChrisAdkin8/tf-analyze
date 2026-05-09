# 💡 ROB-AWS-REDSHIFT-001 — Redshift cluster has no automated snapshot retention

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Redshift cluster has no automated snapshot retention.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_redshift_cluster` (`automated_snapshot_retention_period`) matching `/^0$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_redshift_cluster` has `automated_snapshot_retention_period = 0`.
Setting retention to 0 disables automated snapshots entirely. Without
snapshots, accidental data deletion or cluster corruption cannot be
recovered without a full reload from source systems.

## Why it likely fired

`aws_redshift_cluster` has `automated_snapshot_retention_period = 0`.
Setting retention to 0 disables automated snapshots entirely. Without
snapshots, accidental data deletion or cluster corruption cannot be
recovered without a full reload from source systems.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-REDSHIFT-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set a non-zero retention period:

    resource "aws_redshift_cluster" "main" {
      # ...
      automated_snapshot_retention_period = 7
    }

Maximum is 35 days. For longer-term retention, copy snapshots to S3 via
`aws_redshift_snapshot_copy_grant`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_redshift_cluster" "example" {
  cluster_identifier                  = "example"
  automated_snapshot_retention_period = 7
}
```

## Verification

```sh
`aws redshift describe-clusters --cluster-identifier <id> \
  --query 'Clusters[*].AutomatedSnapshotRetentionPeriod'`
must return a value greater than 0.
```

## References

**SOC 2 Trust Services Criteria**
  - `A1.2`

**Source**
  - [`catalog/ROB-AWS-REDSHIFT-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-REDSHIFT-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-REDSHIFT-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-REDSHIFT-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-REDSHIFT-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
