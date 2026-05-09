# ℹ️ STK-AWS-LAMBDA-003 — Lambda function active X-Ray tracing not configured

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

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
