---
title: "STK-AWS-LAMBDA-003 — Lambda function active X-Ray tracing not configured"
description: "tf-analyze rule STK-AWS-LAMBDA-003 (LOW · stack): Lambda function active X-Ray tracing not configured"
keywords: "stack, low, terraform, iac, aws"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AWS-LAMBDA-003 \u2014 Lambda function active X-Ray tracing not configured",
  "description": "Add a `tracing_config` block with `mode = \"Active\"`:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AWS-LAMBDA-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AWS-LAMBDA-003/"
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
  "keywords": "stack, low, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ℹ️ STK-AWS-LAMBDA-003 — Lambda function active X-Ray tracing not configured

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AWS-LAMBDA-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AWS-LAMBDA-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AWS-LAMBDA-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Lambda function active X-Ray tracing not configured.** This rule has `default_urgency: LOW` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_lambda_function` (`tracing_config`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_lambda_function` has no `tracing_config` block. The default
mode is `PassThrough` — X-Ray traces are emitted only when an
upstream caller has already opened a trace segment. Without
`Active` mode the function never appears independently in the
X-Ray service map and latency/error root-causes cannot be traced.

## Why it likely fired

`aws_lambda_function` has no `tracing_config` block. The default
mode is `PassThrough` — X-Ray traces are emitted only when an
upstream caller has already opened a trace segment. Without
`Active` mode the function never appears independently in the
X-Ray service map and latency/error root-causes cannot be traced.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AWS-LAMBDA-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `tracing_config` block with `mode = "Active"`:

    resource "aws_lambda_function" "processor" {
      # ...
      tracing_config {
        mode = "Active"
      }
    }

Grant the execution role `xray:PutTraceSegments` and
`xray:PutTelemetryRecords`. `Active` mode samples all invocations;
adjust the X-Ray sampling rules if cost is a concern. For
cost-sensitive batch functions, `PassThrough` with sampling on the
upstream trigger is acceptable — document the choice.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_lambda_function" "example" {
  # ... other arguments ...
  tracing_config {
    mode = "Active"
  }
}
```

## Verification

```sh
`aws lambda get-function-configuration --function-name <name> \
  --query 'TracingConfig.Mode'`
must return `Active`.
```

## References

**Source**
  - [`catalog/STK-AWS-LAMBDA-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AWS-LAMBDA-003.yaml) — canonical YAML

## Family

See also rules in the `STK-AWS-LAMBDA-*` family:

- [`STK-AWS-LAMBDA-001`](./STK-AWS-LAMBDA-001.md) — Lambda function uses end-of-life runtime
- [`STK-AWS-LAMBDA-002`](./STK-AWS-LAMBDA-002.md) — Lambda function missing dead-letter queue configuration

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AWS-LAMBDA-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AWS-LAMBDA-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AWS-LAMBDA-003
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
