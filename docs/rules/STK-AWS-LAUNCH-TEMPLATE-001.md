# ⚠️ STK-AWS-LAUNCH-TEMPLATE-001 — EC2 launch template does not enforce IMDSv2

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **EC2 launch template does not enforce IMDSv2.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. _Conditional: only applies when `aws ≥ 3.0`._

## What this checks

1. **`resource_missing_arg`** on `aws_launch_template` (`metadata_options.http_tokens`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_launch_template` without `metadata_options { http_tokens = "required" }`.
Launch templates without IMDSv2 enforcement allow nodes (EC2 and EKS node
groups using this template) to call IMDSv1, which is exploitable via SSRF.
2. **`hcl_attr`** on `aws_launch_template` (`metadata_options.http_tokens`) not equal to `"required"` — _an attribute value differs from the expected literal._
  `aws_launch_template` with `metadata_options.http_tokens` set to something
other than `"required"` — IMDSv2 not enforced.

## Why it likely fired

`aws_launch_template` without `metadata_options { http_tokens = "required" }`.
Launch templates without IMDSv2 enforcement allow nodes (EC2 and EKS node
groups using this template) to call IMDSv1, which is exploitable via SSRF.

`aws_launch_template` with `metadata_options.http_tokens` set to something
other than `"required"` — IMDSv2 not enforced.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AWS-LAUNCH-TEMPLATE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enforce IMDSv2 on every launch template:

    resource "aws_launch_template" "app" {
      # ...
      metadata_options {
        http_endpoint               = "enabled"
        http_tokens                 = "required"
        http_put_response_hop_limit = 1
      }
    }

For EKS managed node groups, the launch template feeds into
`aws_eks_node_group.launch_template`. Nodes without IMDSv2 are
exploitable from any pod with SSRF capability — the pod can reach
169.254.169.254 and steal the node's IAM role credentials.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_launch_template" "example" {
  name = "example"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
}
```

## Verification

```sh
`aws ec2 describe-launch-template-versions --launch-template-id <id>` —
`MetadataOptions.HttpTokens` must be `required`. Re-run tf-analyze mode:verify-fixed.
```

## References

**MITRE ATT&CK**
  - [`T1552.005`](https://attack.mitre.org/techniques/T1552/005/)

**Related rules**
  - [`SEC-AWS-SSRF-001`](./SEC-AWS-SSRF-001.md)
  - [`STK-AWS-EKS-001`](./STK-AWS-EKS-001.md)

**Source**
  - [`catalog/STK-AWS-LAUNCH-TEMPLATE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AWS-LAUNCH-TEMPLATE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AWS-LAUNCH-TEMPLATE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AWS-LAUNCH-TEMPLATE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AWS-LAUNCH-TEMPLATE-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
