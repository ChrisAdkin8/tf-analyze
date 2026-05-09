# ⚠️ SEC-AWS-CLOUDFRONT-001 — CloudFront distribution serves HTTP without redirect

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **CloudFront distribution serves HTTP without redirect.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_body_contains`** on `aws_cloudfront_distribution` matching `/viewer_protocol_policy\s*=\s*"allow-all"/` — _the resource body matches a regex inside the block._
  A `default_cache_behavior` or `ordered_cache_behavior` block has
`viewer_protocol_policy = "allow-all"`, which serves content over
plain HTTP. Session cookies, API tokens, and credentials cross the
network in cleartext between CloudFront and the viewer.

## Why it likely fired

A `default_cache_behavior` or `ordered_cache_behavior` block has
`viewer_protocol_policy = "allow-all"`, which serves content over
plain HTTP. Session cookies, API tokens, and credentials cross the
network in cleartext between CloudFront and the viewer.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-CLOUDFRONT-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `viewer_protocol_policy = "redirect-to-https"` (or `"https-only"`)
in every cache-behavior block:

    resource "aws_cloudfront_distribution" "cdn" {
      default_cache_behavior {
        viewer_protocol_policy = "redirect-to-https"
        # ...
      }
      ordered_cache_behavior {
        viewer_protocol_policy = "redirect-to-https"
        # ...
      }
    }

`redirect-to-https` is preferred over `https-only` for public-facing
distributions where existing HTTP URLs may be indexed — it enforces
encryption without returning 403s to legacy links.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_cloudfront_distribution" "example" {
  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "example"
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }
}
```

## Verification

```sh
`aws cloudfront get-distribution --id <id> \
  --query 'Distribution.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy'`
must return `redirect-to-https` or `https-only`. Repeat for every
`CacheBehaviors.Items[*].ViewerProtocolPolicy`.
```

## References

**MITRE ATT&CK**
  - [`T1071.001`](https://attack.mitre.org/techniques/T1071/001/)

**Source**
  - [`catalog/SEC-AWS-CLOUDFRONT-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-CLOUDFRONT-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-CLOUDFRONT-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-CLOUDFRONT-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-CLOUDFRONT-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
