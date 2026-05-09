# 💡 OPS-AWS-TAGS-001 — AWS resource missing tags

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: ops](https://img.shields.io/badge/section-ops-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **AWS resource missing tags.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_instance` (`tags`) — _the resource is missing a required attribute (or nested attribute path)._
2. **`resource_missing_arg`** on `aws_s3_bucket` (`tags`) — _the resource is missing a required attribute (or nested attribute path)._
3. **`resource_missing_arg`** on `aws_db_instance` (`tags`) — _the resource is missing a required attribute (or nested attribute path)._
4. **`resource_missing_arg`** on `aws_eks_cluster` (`tags`) — _the resource is missing a required attribute (or nested attribute path)._
5. **`resource_missing_arg`** on `aws_lambda_function` (`tags`) — _the resource is missing a required attribute (or nested attribute path)._
6. **`resource_missing_arg`** on `aws_vpc` (`tags`) — _the resource is missing a required attribute (or nested attribute path)._
7. **`resource_missing_arg`** on `aws_dynamodb_table` (`tags`) — _the resource is missing a required attribute (or nested attribute path)._
8. **`resource_missing_arg`** on `aws_rds_cluster` (`tags`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain OPS-AWS-TAGS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `tags` block with at minimum `Environment`, `ManagedBy = "terraform"`,
and `Project`. Use a `locals` block for shared tags:

    locals {
      common_tags = {
        Environment = var.environment
        ManagedBy   = "terraform"
        Project     = var.project_name
      }
    }

    resource "aws_instance" "app" {
      # ...
      tags = merge(local.common_tags, { Name = "app" })
    }

Tags are required for cost allocation, compliance reporting, and
automated cleanup. AWS Cost Explorer cannot break down spend by
workload without consistent tags.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_instance" "example" {
  # ... other arguments ...
  tags = {
    Environment = "prod"
    Owner       = "platform-team"
    Project     = "my-project"
  }
}
```

## Verification

```sh
`aws resourcegroupstaggingapi get-resources --tag-filters Key=ManagedBy,Values=terraform`
must return the resource. Or review the AWS Tag Editor in the console.
```

## References

**Source**
  - [`catalog/OPS-AWS-TAGS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/OPS-AWS-TAGS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain OPS-AWS-TAGS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore OPS-AWS-TAGS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - OPS-AWS-TAGS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
