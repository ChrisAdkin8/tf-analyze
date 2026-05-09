# ⚠️ ROB-AWS-LIFECYCLE-002 — S3 bucket has force_destroy enabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **S3 bucket has force_destroy enabled.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_s3_bucket` (`force_destroy`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_s3_bucket` with `force_destroy = true`. Terraform will silently
delete every object in the bucket — including objects written by
applications after the infrastructure was provisioned — on the next
`terraform destroy`. This makes data loss a single command away.

## Why it likely fired

`aws_s3_bucket` with `force_destroy = true`. Terraform will silently
delete every object in the bucket — including objects written by
applications after the infrastructure was provisioned — on the next
`terraform destroy`. This makes data loss a single command away.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-LIFECYCLE-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove `force_destroy = true` from production buckets:

    resource "aws_s3_bucket" "app" {
      bucket = "app-data"
      # force_destroy = true  # remove this line
    }

For development/test environments where force_destroy is intentional,
add an inline comment explaining why and suppress the finding:
    # tf-analyze:ignore ROB-AWS-LIFECYCLE-002
    force_destroy = true  # test env only — data is ephemeral

Pair production buckets with `lifecycle { prevent_destroy = true }` for
a double guard.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_s3_bucket" "example" {
  # ... other arguments ...
  force_destroy = false
}
```

## Verification

```sh
`aws s3api get-bucket-policy --bucket <name>` (policy cannot re-enable
forced deletion). Confirm `force_destroy` is absent or `false` in
`terraform show`.
```

## References

**Source**
  - [`catalog/ROB-AWS-LIFECYCLE-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-LIFECYCLE-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-LIFECYCLE-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-LIFECYCLE-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-LIFECYCLE-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
