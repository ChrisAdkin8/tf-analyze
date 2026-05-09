# ⚠️ SEC-AWS-COGNITO-001 — Cognito user pool MFA not enabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Cognito user pool MFA not enabled.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_cognito_user_pool` (`mfa_configuration`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_cognito_user_pool` has no `mfa_configuration` argument. The
default is `"OFF"` — users authenticate with password alone.
Credential-stuffing and phishing attacks succeed without a second
factor.
2. **`resource_arg`** on `aws_cognito_user_pool` (`mfa_configuration`) matching `/OFF/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_cognito_user_pool` explicitly sets `mfa_configuration = "OFF"`.
Password-only authentication is confirmed; account takeover is
trivial for any attacker with valid credentials.

## Why it likely fired

`aws_cognito_user_pool` has no `mfa_configuration` argument. The
default is `"OFF"` — users authenticate with password alone.
Credential-stuffing and phishing attacks succeed without a second
factor.

`aws_cognito_user_pool` explicitly sets `mfa_configuration = "OFF"`.
Password-only authentication is confirmed; account takeover is
trivial for any attacker with valid credentials.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-COGNITO-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `mfa_configuration = "ON"` and configure software token MFA:

    resource "aws_cognito_user_pool" "users" {
      mfa_configuration = "ON"

      software_token_mfa_configuration {
        enabled = true
      }
    }

`"OPTIONAL"` allows self-enrolment but is not a durable security
control — users may skip MFA. For regulated workloads, `"ON"` with
TOTP (or hardware keys via `sms_mfa_configuration`) is required.
Existing users will be prompted at next login.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_cognito_user_pool" "example" {
  # ... other arguments ...
  mfa_configuration = "ON"
  software_token_mfa_configuration {
    enabled = true
  }
}
```

## Verification

```sh
`aws cognito-idp describe-user-pool --user-pool-id <id> \
  --query 'UserPool.MfaConfiguration'`
must return `ON`.
```

## References

**MITRE ATT&CK**
  - [`T1556.006`](https://attack.mitre.org/techniques/T1556/006/)

**Source**
  - [`catalog/SEC-AWS-COGNITO-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-COGNITO-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-COGNITO-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-COGNITO-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-COGNITO-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
