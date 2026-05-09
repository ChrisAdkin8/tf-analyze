# 💡 STK-AWS-ROUTE53-001 — Route 53 hosted zone missing DNSSEC signing

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **Route 53 hosted zone missing DNSSEC signing.** This rule has `default_urgency: MEDIUM` and operates on a environment blast radius. 

## What this checks

1. **`resource_absent`** on `aws_route53_key_signing_key` — _the corpus is missing a resource type we expected to find given other resources present._
  `aws_route53_zone` present but no `aws_route53_key_signing_key` in the
repository. Without DNSSEC, DNS responses for the zone can be spoofed
by a man-in-the-middle — an attacker who can intercept DNS traffic can
redirect users to attacker-controlled infrastructure. DNSSEC signs all
DNS records, allowing resolvers to detect tampered responses.

## Why it likely fired

`aws_route53_zone` present but no `aws_route53_key_signing_key` in the
repository. Without DNSSEC, DNS responses for the zone can be spoofed
by a man-in-the-middle — an attacker who can intercept DNS traffic can
redirect users to attacker-controlled infrastructure. DNSSEC signs all
DNS records, allowing resolvers to detect tampered responses.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AWS-ROUTE53-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable DNSSEC on the hosted zone:

    resource "aws_kms_key" "dnssec" {
      customer_master_key_spec = "ECC_NIST_P256"
      deletion_window_in_days  = 7
      key_usage                = "SIGN_VERIFY"
      policy = data.aws_iam_policy_document.dnssec.json
    }

    resource "aws_route53_key_signing_key" "main" {
      hosted_zone_id             = aws_route53_zone.main.zone_id
      key_management_service_arn = aws_kms_key.dnssec.arn
      name                       = "main"
    }

    resource "aws_route53_hosted_zone_dnssec" "main" {
      hosted_zone_id = aws_route53_key_signing_key.main.hosted_zone_id
      depends_on     = [aws_route53_key_signing_key.main]
    }

After enabling, submit the DS record to your domain registrar so the
parent zone can verify the chain of trust.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_route53_zone" "example" {
  name = "example.com"
}
resource "aws_route53_key_signing_key" "example" {
  hosted_zone_id             = aws_route53_zone.example.id
  key_management_service_arn = aws_kms_key.dnssec.arn
  name                       = "example"
}
resource "aws_route53_hosted_zone_dnssec" "example" {
  depends_on     = [aws_route53_key_signing_key.example]
  hosted_zone_id = aws_route53_key_signing_key.example.hosted_zone_id
}
```

## Verification

```sh
`aws route53 get-dnssec --hosted-zone-id <id> \
  --query 'Status.ServedSigning'`
must return `"SIGNING"`.
```

## References

**Source**
  - [`catalog/STK-AWS-ROUTE53-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AWS-ROUTE53-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AWS-ROUTE53-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AWS-ROUTE53-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AWS-ROUTE53-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
