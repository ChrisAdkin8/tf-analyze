# 💡 ROB-AWS-S3-001 — S3 bucket versioning disabled or suspended

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **S3 bucket versioning disabled or suspended.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_s3_bucket_versioning` (`versioning_configuration.status`) matching `/^(Disabled|Suspended)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  S3 bucket versioning disabled or suspended
2. **`resource_missing_arg`** on `aws_s3_bucket` (`versioning`) — _the resource is missing a required attribute (or nested attribute path)._
  S3 bucket missing versioning block (pre-v4 provider inline block)

## Why it likely fired

S3 bucket versioning disabled or suspended

S3 bucket missing versioning block (pre-v4 provider inline block)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-S3-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `versioning_configuration { status = "Enabled" }` on the
`aws_s3_bucket_versioning` resource associated with every S3 bucket
that holds important data. Versioning protects against accidental
overwrites and deletions by retaining prior object versions. Add a
lifecycle rule expiring non-current versions after 90 days to control
storage costs:

  noncurrent_version_expiration {
    noncurrent_days = 90
  }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}
```

## Verification

Run `aws s3api get-bucket-versioning --bucket <name>` and confirm
`Status` is `Enabled`. Run `terraform plan` and verify no diff shows
`status = "Suspended"` or `status = "Disabled"`.

## References

**CIS Benchmark**
  - `CIS 2.1.2`

**Source**
  - [`catalog/ROB-AWS-S3-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-S3-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-S3-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-S3-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-S3-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
