---
title: "STK-AWS-LAMBDA-001 — Lambda function uses end-of-life runtime"
description: "tf-analyze rule STK-AWS-LAMBDA-001 (HIGH · stack): Lambda function uses end-of-life runtime"
keywords: "stack, high, terraform, iac, aws"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AWS-LAMBDA-001 \u2014 Lambda function uses end-of-life runtime",
  "description": "Upgrade the `runtime` to a currently supported version. EOL runtimes\nno longer receive security patches or OS updates from AWS, meaning known\nCVEs accumulate silently. AWS may also block deployment of new functions\nusing deprecated runtimes",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AWS-LAMBDA-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AWS-LAMBDA-001/"
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
  "keywords": "stack, high, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-AWS-LAMBDA-001 — Lambda function uses end-of-life runtime

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AWS-LAMBDA-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Lambda function uses end-of-life runtime.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_lambda_function` (`runtime`) matching `/^(nodejs10\.x|nodejs12\.x|nodejs14\.x|python2\.7|python3\.6|python3\.7|ruby2\.5|java8|go1\.x|dotnetcore2\.1|dotnetcore3\.1)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Lambda function using an end-of-life runtime no longer patched by AWS

## Why it likely fired

Lambda function using an end-of-life runtime no longer patched by AWS

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AWS-LAMBDA-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Upgrade the `runtime` to a currently supported version. EOL runtimes
no longer receive security patches or OS updates from AWS, meaning known
CVEs accumulate silently. AWS may also block deployment of new functions
using deprecated runtimes after a deprecation deadline.
See https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
for the current support matrix and deprecation schedule. Common
replacements: `nodejs14.x` → `nodejs22.x`, `python3.7` → `python3.13`,
`dotnetcore3.1` → `dotnet8`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_lambda_function" "example" {
  function_name = "example"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "function.zip"
}
```

## Verification

Run `aws lambda get-function-configuration --function-name <name>` and
confirm `Runtime` is a currently supported value. Run `terraform plan`
and verify the runtime argument references a non-EOL identifier.

## References

**Source**
  - [`catalog/STK-AWS-LAMBDA-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AWS-LAMBDA-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AWS-LAMBDA-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AWS-LAMBDA-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AWS-LAMBDA-001
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
