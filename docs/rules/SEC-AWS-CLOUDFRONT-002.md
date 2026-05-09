# 💡 SEC-AWS-CLOUDFRONT-002 — CloudFront distribution missing access logging

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **CloudFront distribution missing access logging.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_cloudfront_distribution` (`logging_config`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_cloudfront_distribution` has no `logging_config` block.
Without access logging, viewer IP addresses, requested paths,
cache-hit/miss status, bytes transferred, and HTTP status codes
are not recorded. Post-incident forensics and abuse investigation
have no CloudFront-layer evidence.

## Why it likely fired

`aws_cloudfront_distribution` has no `logging_config` block.
Without access logging, viewer IP addresses, requested paths,
cache-hit/miss status, bytes transferred, and HTTP status codes
are not recorded. Post-incident forensics and abuse investigation
have no CloudFront-layer evidence.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-CLOUDFRONT-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `logging_config` block pointing to an S3 bucket:

    resource "aws_cloudfront_distribution" "cdn" {
      logging_config {
        bucket          = aws_s3_bucket.cf_logs.bucket_domain_name
        include_cookies = false
        prefix          = "cf/"
      }
      # ...
    }

Grant the CloudFront logging principal `s3:PutObject` on the target
bucket via a bucket policy. Enable versioning and lifecycle rules on
the log bucket — CloudFront generates high log volume.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_cloudfront_distribution" "example" {
  # ... other arguments ...
  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.logs.bucket_domain_name
    prefix          = "cloudfront/"
  }
}
```

## Verification

```sh
`aws cloudfront get-distribution --id <id> \
  --query 'Distribution.DistributionConfig.Logging.Enabled'`
must return `true`.
```

## References

**MITRE ATT&CK**
  - [`T1071.001`](https://attack.mitre.org/techniques/T1071/001/)

**Source**
  - [`catalog/SEC-AWS-CLOUDFRONT-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-CLOUDFRONT-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-CLOUDFRONT-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-CLOUDFRONT-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-CLOUDFRONT-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
