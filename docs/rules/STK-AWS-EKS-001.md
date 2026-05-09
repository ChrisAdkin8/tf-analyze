# ⚠️ STK-AWS-EKS-001 — EKS cluster API endpoint private access not enabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **EKS cluster API endpoint private access not enabled.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_eks_cluster` (`vpc_config.endpoint_private_access`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_eks_cluster` without `vpc_config { endpoint_private_access = true }`.
Without private endpoint access, workloads running in the cluster VPC
must reach the API server over the internet rather than a private
endpoint, increasing exposure.
2. **`hcl_attr`** on `aws_eks_cluster` (`vpc_config.endpoint_private_access`) not equal to `True` — _an attribute value differs from the expected literal._
  `endpoint_private_access = false` means nodes communicate with the
API server over the public internet even from within the cluster VPC.

## Why it likely fired

`aws_eks_cluster` without `vpc_config { endpoint_private_access = true }`.
Without private endpoint access, workloads running in the cluster VPC
must reach the API server over the internet rather than a private
endpoint, increasing exposure.

`endpoint_private_access = false` means nodes communicate with the
API server over the public internet even from within the cluster VPC.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AWS-EKS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable private endpoint access and restrict (or disable) public access:

    resource "aws_eks_cluster" "app" {
      vpc_config {
        endpoint_private_access = true
        endpoint_public_access  = false  # disable public entirely, or...
        # endpoint_public_access  = true  # ...keep public but restrict CIDRs:
        # public_access_cidrs     = ["203.0.113.0/24"]
      }
    }

With both access types enabled, use `public_access_cidrs` to limit which
CIDRs can reach the public endpoint (e.g., your CI runner egress IPs only).
Equivalent to GKE `private_cluster_config.enable_private_endpoint`.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_eks_cluster" "example" {
  name     = "example"
  role_arn = aws_iam_role.eks.arn
  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
  }
}
```

## Verification

```sh
`aws eks describe-cluster --name <name> \
  --query 'cluster.resourcesVpcConfig.endpointPrivateAccess'`
must return `true`.
```

## References

**CIS Benchmark**
  - `CIS 5.4.3`

**Source**
  - [`catalog/STK-AWS-EKS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AWS-EKS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AWS-EKS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AWS-EKS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AWS-EKS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
