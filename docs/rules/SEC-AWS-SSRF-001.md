# ⚠️ SEC-AWS-SSRF-001 — EC2 instance metadata service v1 enabled (IMDSv2 not enforced)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **EC2 instance metadata service v1 enabled (IMDSv2 not enforced).** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_instance` (`metadata_options`) — _the resource is missing a required attribute (or nested attribute path)._
  EC2 instance missing metadata_options block (IMDSv1 allowed by default)
2. **`resource_arg`** on `aws_instance` (`metadata_options.http_tokens`) matching `/^optional$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  EC2 instance with http_tokens = "optional" (IMDSv1 still allowed)

## Why it likely fired

EC2 instance missing metadata_options block (IMDSv1 allowed by default)

EC2 instance with http_tokens = "optional" (IMDSv1 still allowed)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-SSRF-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `metadata_options` block to every `aws_instance` that enforces
IMDSv2:

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

IMDSv1 is a pre-authenticated HTTP endpoint accessible from within the
instance. An SSRF vulnerability in any application on the instance can
retrieve the instance's IAM credentials from `http://169.254.169.254/`.
This was the root cause of the Capital One breach in 2019. IMDSv2
requires a session-oriented PUT request before any GET, which is
incompatible with simple SSRF payloads.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
metadata_options {
  http_endpoint               = "enabled"
  http_tokens                 = "required"
  http_put_response_hop_limit = 1
}
```

_Changing metadata_options on a running EC2 instance forces replacement in Terraform. Schedule this change during a maintenance window._

## Verification

Run `aws ec2 describe-instances --instance-ids <id>` and confirm
`MetadataOptions.HttpTokens` is `required`. Run `terraform plan` and
verify the metadata_options block is present with `http_tokens = "required"`.

## References

**CIS Benchmark**
  - `CIS 5.6`

**Source**
  - [`catalog/SEC-AWS-SSRF-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-SSRF-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-SSRF-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-SSRF-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-SSRF-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
