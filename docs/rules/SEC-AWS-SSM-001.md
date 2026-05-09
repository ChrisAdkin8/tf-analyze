# ⚠️ SEC-AWS-SSM-001 — SSM Parameter Store parameter not encrypted as SecureString

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **SSM Parameter Store parameter not encrypted as SecureString.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_ssm_parameter` (`type`) matching `/^(?:String|StringList)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_ssm_parameter` has `type = "String"` or `type = "StringList"`.
Parameters of these types are stored and transmitted in plaintext.
Any IAM principal with `ssm:GetParameter` access can retrieve the value
without any decryption key, and the value appears in CloudTrail logs.
Credentials, API keys, and configuration secrets must use `SecureString`.

## Why it likely fired

`aws_ssm_parameter` has `type = "String"` or `type = "StringList"`.
Parameters of these types are stored and transmitted in plaintext.
Any IAM principal with `ssm:GetParameter` access can retrieve the value
without any decryption key, and the value appears in CloudTrail logs.
Credentials, API keys, and configuration secrets must use `SecureString`.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-SSM-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Use `type = "SecureString"` with a customer-managed KMS key for any
parameter that contains sensitive data:

    resource "aws_ssm_parameter" "db_password" {
      name   = "/app/db/password"
      type   = "SecureString"
      value  = var.db_password
      key_id = aws_kms_key.ssm.arn
    }

`String` and `StringList` are acceptable only for non-sensitive configuration
values (e.g., environment name, region, feature flags).

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_ssm_parameter" "example" {
  name   = "/app/secret"
  type   = "SecureString"
  value  = var.secret_value
  key_id = aws_kms_key.ssm.arn
}
```

## Verification

```sh
`aws ssm describe-parameters --filters 'Key=Name,Values=<name>' \
  --query 'Parameters[*].Type'`
must return `SecureString`.
```

## References

**CIS Benchmark**
  - `CIS 3.10` — Ensure that encryption at rest is enabled for SSM parameters

**PCI-DSS**
  - `Req-3.5`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**Source**
  - [`catalog/SEC-AWS-SSM-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-SSM-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-SSM-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-SSM-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-SSM-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
