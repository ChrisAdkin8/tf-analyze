---
title: "SEC-AWS-APIGW-001 — API Gateway stage missing access log destination"
description: "tf-analyze rule SEC-AWS-APIGW-001 (MEDIUM · security): API Gateway stage missing access log destination"
keywords: "security, medium, terraform, iac, aws, mitre-T1190, cwe-284, d3-iaa"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-APIGW-001 \u2014 API Gateway stage missing access log destination",
  "description": "Add an `access_log_settings` block pointing to a CloudWatch log group:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-APIGW-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-APIGW-001/"
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
  "keywords": "security, medium, terraform, MITRE T1190, CWE-284, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AWS-APIGW-001 — API Gateway stage missing access log destination

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-APIGW-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-APIGW-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-APIGW-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

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

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**MITRE D3FEND**
  - [`D3-IAA`](https://d3fend.mitre.org/technique/D3-IAA/)

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
