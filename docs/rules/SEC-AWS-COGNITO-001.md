---
title: "SEC-AWS-COGNITO-001 — Cognito user pool MFA not enabled"
description: "tf-analyze rule SEC-AWS-COGNITO-001 (HIGH · security): Cognito user pool MFA not enabled"
keywords: "security, high, terraform, iac, aws, mitre-T1556.006"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-COGNITO-001 \u2014 Cognito user pool MFA not enabled",
  "description": "Set `mfa_configuration = \"ON\"` and configure software token MFA:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-COGNITO-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-COGNITO-001/"
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
  "keywords": "security, high, terraform, MITRE T1556.006",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-COGNITO-001 — Cognito user pool MFA not enabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-COGNITO-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-COGNITO-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-COGNITO-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

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
