---
title: "STK-AWS-EKS-003 — EKS cluster Kubernetes Secrets not encrypted with KMS"
description: "tf-analyze rule STK-AWS-EKS-003 (HIGH · stack): EKS cluster Kubernetes Secrets not encrypted with KMS"
keywords: "stack, high, terraform, iac, aws, cis-5.3.1"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AWS-EKS-003 \u2014 EKS cluster Kubernetes Secrets not encrypted with KMS",
  "description": "Add an `encryption_config` block pointing to a customer-managed KMS key:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AWS-EKS-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AWS-EKS-003/"
  },
  "author": {
    "@type": "Organization",
    "name": "tf-analyze"
  },
  "publisher": {
    "@type": "Organization",
    "name": "tf-analyze",
    "url": "https://chrisadkin8.github.io/tf-analyze"
  },
  "keywords": "stack, high, terraform, CIS 5.3.1",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-AWS-EKS-003 — EKS cluster Kubernetes Secrets not encrypted with KMS

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AWS-EKS-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AWS-EKS-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AWS-EKS-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **EKS cluster Kubernetes Secrets not encrypted with KMS.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. _Conditional: only applies when `aws ≥ 3.0`._

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

## Family

See also rules in the `STK-AWS-EKS-*` family:

- [`STK-AWS-EKS-001`](./STK-AWS-EKS-001.md) — EKS cluster API endpoint private access not enabled
- [`STK-AWS-EKS-002`](./STK-AWS-EKS-002.md) — EKS cluster control plane logging not enabled
- [`STK-AWS-EKS-004`](./STK-AWS-EKS-004.md) — EKS cluster missing OIDC provider for IRSA
- [`STK-AWS-EKS-005`](./STK-AWS-EKS-005.md) — EKS cluster missing audit log type in enabled_cluster_log_types

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
{% if site.giscus.enabled %}
---

## Discussion

<script src="https://giscus.app/client.js"
        data-repo="{{ site.giscus.repo }}"
        data-repo-id="{{ site.giscus.repo_id }}"
        data-category="{{ site.giscus.category }}"
        data-category-id="{{ site.giscus.category_id }}"
        data-mapping="{{ site.giscus.mapping }}"
        data-strict="0"
        data-reactions-enabled="{{ site.giscus.reactions }}"
        data-emit-metadata="{{ site.giscus.emit_metadata }}"
        data-input-position="{{ site.giscus.input_position }}"
        data-theme="{{ site.giscus.theme }}"
        data-lang="en"
        crossorigin="anonymous"
        async>
</script>

{% endif %}
