# ⚠️ STK-AWS-EKS-005 — EKS cluster missing audit log type in enabled_cluster_log_types

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **EKS cluster missing audit log type in enabled_cluster_log_types.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_arg`** on `aws_eks_cluster` (`enabled_cluster_log_types`) — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_eks_cluster` with `enabled_cluster_log_types` set but the list
does not include `"audit"`. The audit log type captures every API call
made to the Kubernetes API server — kubectl commands, pod service-account
token usage, RBAC decisions. Without it, a compromised pod credential
leaves no trail. STK-AWS-EKS-002 catches complete absence of the
attribute; this rule catches the partial-config case where the attribute
exists but the most security-critical type is missing.

Also checks for `"authenticator"` absence — without it, IAM
authentication events (including failed attempts) are not logged.
2. **`resource_arg`** on `aws_eks_cluster` (`enabled_cluster_log_types`) — _the resource declares the named attribute, but its value matches the rule's pattern._
  `enabled_cluster_log_types` present but missing the `"authenticator"`
type. Authenticator logs record every IAM-based authentication attempt
to the API server — the first evidence of credential compromise.

## Why it likely fired

`aws_eks_cluster` with `enabled_cluster_log_types` set but the list
does not include `"audit"`. The audit log type captures every API call
made to the Kubernetes API server — kubectl commands, pod service-account
token usage, RBAC decisions. Without it, a compromised pod credential
leaves no trail. STK-AWS-EKS-002 catches complete absence of the
attribute; this rule catches the partial-config case where the attribute
exists but the most security-critical type is missing.

Also checks for `"authenticator"` absence — without it, IAM
authentication events (including failed attempts) are not logged.

`enabled_cluster_log_types` present but missing the `"authenticator"`
type. Authenticator logs record every IAM-based authentication attempt
to the API server — the first evidence of credential compromise.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AWS-EKS-005` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable all five control-plane log types. The `audit` and `authenticator`
types are the most security-critical:

```hcl
resource "aws_eks_cluster" "app" {
  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler",
  ]
}
```

Note: STK-AWS-EKS-002 fires when `enabled_cluster_log_types` is absent
entirely. This rule (STK-AWS-EKS-005) fires when the attribute exists but
critical types are missing — both rules must pass.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_eks_cluster" "example" {
  name     = "example"
  role_arn = aws_iam_role.eks.arn
  enabled_cluster_log_types = [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ]
  vpc_config { subnet_ids = var.subnet_ids }
}
```

## Verification

```sh
```
aws eks describe-cluster --name <name> \
  --query 'cluster.logging.clusterLogging[?enabled==`true`].types[]'
```
Output must include `audit` and `authenticator`.
```

## References

**CIS Benchmark**
  - `CIS 5.4.1`

**Source**
  - [`catalog/STK-AWS-EKS-005.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AWS-EKS-005.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AWS-EKS-005    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AWS-EKS-005` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AWS-EKS-005
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
