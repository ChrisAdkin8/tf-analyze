# 💡 STK-AWS-EKS-004 — EKS cluster missing OIDC provider for IRSA

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **EKS cluster missing OIDC provider for IRSA.** This rule has `default_urgency: MEDIUM` and operates on a environment blast radius. 

## What this checks

1. **`resource_absent`** on `aws_iam_openid_connect_provider` — _the corpus is missing a resource type we expected to find given other resources present._
  `aws_eks_cluster` present but no `aws_iam_openid_connect_provider`
in the repository. Without an OIDC provider, pods cannot use IAM
Roles for Service Accounts (IRSA). Instead, every pod on a node
inherits the node IAM role — granting all workloads the union of all
permissions any pod on that node needs, violating least privilege.
IRSA is the AWS equivalent of GKE Workload Identity.

## Why it likely fired

`aws_eks_cluster` present but no `aws_iam_openid_connect_provider`
in the repository. Without an OIDC provider, pods cannot use IAM
Roles for Service Accounts (IRSA). Instead, every pod on a node
inherits the node IAM role — granting all workloads the union of all
permissions any pod on that node needs, violating least privilege.
IRSA is the AWS equivalent of GKE Workload Identity.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AWS-EKS-004` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Create an OIDC provider backed by the cluster's issuer URL, then bind
pod service accounts to scoped IAM roles:

    data "tls_certificate" "eks" {
      url = aws_eks_cluster.app.identity[0].oidc[0].issuer
    }

    resource "aws_iam_openid_connect_provider" "eks" {
      client_id_list  = ["sts.amazonaws.com"]
      thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
      url             = aws_eks_cluster.app.identity[0].oidc[0].issuer
    }

    resource "aws_iam_role" "pod_role" {
      assume_role_policy = jsonencode({
        Statement = [{
          Effect    = "Allow"
          Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }
          Action    = "sts:AssumeRoleWithWebIdentity"
          Condition = { StringEquals = {
            "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" =
              "system:serviceaccount:default:my-service-account"
          }}
        }]
      })
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
data "tls_certificate" "eks" {
  url = aws_eks_cluster.example.identity[0].oidc[0].issuer
}
resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.example.identity[0].oidc[0].issuer
}
```

## Verification

```sh
`aws iam list-open-id-connect-providers` must include the cluster OIDC
issuer. In-cluster: `kubectl get serviceaccount -n <ns> <sa> -o yaml`
must show `eks.amazonaws.com/role-arn` annotation.
```

## References

**Source**
  - [`catalog/STK-AWS-EKS-004.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AWS-EKS-004.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AWS-EKS-004    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AWS-EKS-004` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AWS-EKS-004
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
