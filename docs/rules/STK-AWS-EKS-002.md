# ⚠️ STK-AWS-EKS-002 — EKS cluster control plane logging not enabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **EKS cluster control plane logging not enabled.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_eks_cluster` (`enabled_cluster_log_types`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_eks_cluster` without `enabled_cluster_log_types`. Control-plane
logs (API server, audit, authenticator, controller manager, scheduler)
are not shipped to CloudWatch Logs. Post-incident investigation and
compliance auditing have no evidence of API activity, authentication
events, or resource modifications.

## Why it likely fired

`aws_eks_cluster` without `enabled_cluster_log_types`. Control-plane
logs (API server, audit, authenticator, controller manager, scheduler)
are not shipped to CloudWatch Logs. Post-incident investigation and
compliance auditing have no evidence of API activity, authentication
events, or resource modifications.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AWS-EKS-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable all five control-plane log types:

    resource "aws_eks_cluster" "app" {
      enabled_cluster_log_types = [
        "api",
        "audit",
        "authenticator",
        "controllerManager",
        "scheduler",
      ]
    }

The `audit` log type is the most critical — it captures every API call
made to the Kubernetes API server, including by pods with service account
tokens. The other types are necessary for diagnosing control-plane issues
and tracing scheduler or controller-manager behaviour.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_eks_cluster" "example" {
  # ... other arguments ...
  enabled_cluster_log_types = [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ]
}
```

## Verification

```sh
`aws eks describe-cluster --name <name> \
  --query 'cluster.logging.clusterLogging[?enabled==\`true\`].types'`
must include `api`, `audit`, `authenticator`, `controllerManager`,
`scheduler`.
```

## References

**CIS Benchmark**
  - `CIS 5.4.1`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**Source**
  - [`catalog/STK-AWS-EKS-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AWS-EKS-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AWS-EKS-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AWS-EKS-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AWS-EKS-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
