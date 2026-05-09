---
title: "STK-AWS-LAMBDA-002 — Lambda function missing dead-letter queue configuration"
description: "tf-analyze rule STK-AWS-LAMBDA-002 (MEDIUM · stack): Lambda function missing dead-letter queue configuration"
keywords: "stack, medium, terraform, iac, aws"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AWS-LAMBDA-002 \u2014 Lambda function missing dead-letter queue configuration",
  "description": "Add a `dead_letter_config` block pointing to an SQS DLQ or SNS topic:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AWS-LAMBDA-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AWS-LAMBDA-002/"
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
  "keywords": "stack, medium, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-AWS-LAMBDA-002 — Lambda function missing dead-letter queue configuration

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AWS-LAMBDA-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Lambda function missing dead-letter queue configuration.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_lambda_function` (`dead_letter_config`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_lambda_function` has no `dead_letter_config` block. Failed
asynchronous invocations are retried twice then silently discarded.
Events from SNS, S3, EventBridge, and other async sources that fail
all retries leave no trace, and there is no replay path.

## Why it likely fired

`aws_lambda_function` has no `dead_letter_config` block. Failed
asynchronous invocations are retried twice then silently discarded.
Events from SNS, S3, EventBridge, and other async sources that fail
all retries leave no trace, and there is no replay path.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AWS-LAMBDA-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `dead_letter_config` block pointing to an SQS DLQ or SNS topic:

    resource "aws_sqs_queue" "dlq" {
      name                       = "${local.name}-dlq"
      message_retention_seconds  = 1209600  # 14 days
    }

    resource "aws_lambda_function" "processor" {
      # ...
      dead_letter_config {
        target_arn = aws_sqs_queue.dlq.arn
      }
    }

Grant the Lambda execution role `sqs:SendMessage` on the DLQ.
For synchronous invocations (API Gateway, ALB) handle errors at the
caller side — DLQ is only relevant for async invocation paths.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_lambda_function" "example" {
  # ... other arguments ...
  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }
}
```

## Verification

```sh
`aws lambda get-function-configuration --function-name <name> \
  --query 'DeadLetterConfig.TargetArn'`
must return a non-null ARN.
```

## References

**Source**
  - [`catalog/STK-AWS-LAMBDA-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AWS-LAMBDA-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AWS-LAMBDA-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AWS-LAMBDA-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AWS-LAMBDA-002
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
