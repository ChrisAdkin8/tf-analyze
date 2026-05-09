# 💡 SEC-AWS-APIGW-001 — API Gateway stage missing access log destination

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **API Gateway stage missing access log destination.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_api_gateway_stage` (`access_log_settings`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_api_gateway_stage` has no `access_log_settings` block. Without
access logs, HTTP method, resource path, caller IP, authentication
outcome, integration latency, and error codes are not recorded.
API-layer evidence is unavailable for incident response, abuse
investigation, and compliance reporting.

## Why it likely fired

`aws_api_gateway_stage` has no `access_log_settings` block. Without
access logs, HTTP method, resource path, caller IP, authentication
outcome, integration latency, and error codes are not recorded.
API-layer evidence is unavailable for incident response, abuse
investigation, and compliance reporting.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-APIGW-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add an `access_log_settings` block pointing to a CloudWatch log group:

    resource "aws_cloudwatch_log_group" "apigw" {
      name              = "/aws/apigateway/${var.api_name}"
      retention_in_days = 90
    }

    resource "aws_api_gateway_stage" "api" {
      stage_name    = "prod"
      rest_api_id   = aws_api_gateway_rest_api.main.id
      deployment_id = aws_api_gateway_deployment.main.id

      access_log_settings {
        destination_arn = aws_cloudwatch_log_group.apigw.arn
      }

      xray_tracing_enabled = true
    }

Also set `method_settings { logging_level = "INFO" }` to capture
execution logs (request/response bodies at INFO level).

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_api_gateway_stage" "example" {
  # ... other arguments ...
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gw.arn
  }
}
```

## Verification

```sh
`aws apigateway get-stage --rest-api-id <id> --stage-name <name> \
  --query 'accessLogSettings.destinationArn'`
must return a non-null CloudWatch log group ARN.
```

## References

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)

**Source**
  - [`catalog/SEC-AWS-APIGW-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-APIGW-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-APIGW-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-APIGW-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-APIGW-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
