# ⚠️ STK-AWS-EKS-003 — EKS cluster Kubernetes Secrets not encrypted with KMS

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **EKS cluster Kubernetes Secrets not encrypted with KMS.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_eks_cluster` (`encryption_config.provider.key_arn`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_eks_cluster` without an `encryption_config { provider { key_arn } }`
block. Kubernetes Secrets — including service account tokens, TLS
certificates, and application credentials — are stored in etcd
encrypted only at the EBS volume level (AWS-managed key). Without
envelope encryption at the application layer, anyone who can read the
EBS snapshot or the etcd backup can access every Secret in the cluster.

## Why it likely fired

`aws_eks_cluster` without an `encryption_config { provider { key_arn } }`
block. Kubernetes Secrets — including service account tokens, TLS
certificates, and application credentials — are stored in etcd
encrypted only at the EBS volume level (AWS-managed key). Without
envelope encryption at the application layer, anyone who can read the
EBS snapshot or the etcd backup can access every Secret in the cluster.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AWS-EKS-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add an `encryption_config` block pointing to a customer-managed KMS key:

    resource "aws_eks_cluster" "app" {
      encryption_config {
        resources = ["secrets"]
        provider {
          key_arn = aws_kms_key.eks.arn
        }
      }
    }

    resource "aws_kms_key" "eks" {
      description             = "EKS secrets encryption"
      enable_key_rotation     = true
      deletion_window_in_days = 30
    }

Equivalent to GKE `database_encryption { state = "ENCRYPTED" }`.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_eks_cluster" "example" {
  name     = "example"
  role_arn = aws_iam_role.eks.arn
  encryption_config {
    provider { key_arn = aws_kms_key.eks.arn }
    resources = ["secrets"]
  }
  vpc_config { subnet_ids = var.subnet_ids }
}
```

## Verification

```sh
`aws eks describe-cluster --name <name> \
  --query 'cluster.encryptionConfig'`
must return a non-empty list with `resources: ["secrets"]`.
```

## References

**CIS Benchmark**
  - `CIS 5.3.1`

**Source**
  - [`catalog/STK-AWS-EKS-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AWS-EKS-003.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AWS-EKS-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AWS-EKS-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AWS-EKS-003
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
