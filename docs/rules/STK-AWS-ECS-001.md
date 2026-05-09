# 💡 STK-AWS-ECS-001 — ECS cluster Container Insights not configured

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **ECS cluster Container Insights not configured.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_ecs_cluster` (`setting`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_ecs_cluster` has no `setting` block. Without the
`containerInsights = "enabled"` setting, per-cluster and per-task
CPU, memory, network I/O, and storage metrics are not published to
CloudWatch. Capacity planning, right-sizing, and anomaly alerting
have no per-container data.

## Why it likely fired

`aws_ecs_cluster` has no `setting` block. Without the
`containerInsights = "enabled"` setting, per-cluster and per-task
CPU, memory, network I/O, and storage metrics are not published to
CloudWatch. Capacity planning, right-sizing, and anomaly alerting
have no per-container data.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AWS-ECS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `setting` block enabling Container Insights:

    resource "aws_ecs_cluster" "app" {
      name = "app"

      setting {
        name  = "containerInsights"
        value = "enabled"
      }
    }

Container Insights is billed per metric per task, per month.
At low task counts the cost is negligible; evaluate for large
clusters before enabling in cost-sensitive environments.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_ecs_cluster" "example" {
  name = "example"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}
```

## Verification

```sh
`aws ecs describe-clusters --clusters <name> --include SETTINGS \
  --query 'clusters[0].settings[?name==\`containerInsights\`].value'`
must return `["enabled"]`.
```

## References

**Source**
  - [`catalog/STK-AWS-ECS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AWS-ECS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AWS-ECS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AWS-ECS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AWS-ECS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
