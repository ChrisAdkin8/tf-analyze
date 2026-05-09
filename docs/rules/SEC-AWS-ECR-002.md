# 💡 SEC-AWS-ECR-002 — ECR repository missing image lifecycle policy

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **ECR repository missing image lifecycle policy.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_absent`** on `aws_ecr_lifecycle_policy` — _the corpus is missing a resource type we expected to find given other resources present._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-ECR-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add an `aws_ecr_lifecycle_policy` resource to expire old images:

    resource "aws_ecr_lifecycle_policy" "main" {
      repository = aws_ecr_repository.main.name

      policy = jsonencode({
        rules = [{
          rulePriority = 1
          description  = "Expire untagged images older than 30 days"
          selection = {
            tagStatus   = "untagged"
            countType   = "sinceImagePushed"
            countUnit   = "days"
            countNumber = 30
          }
          action = { type = "expire" }
        }]
      })
    }

Without a lifecycle policy, ECR accumulates every pushed image indefinitely.
This increases storage cost and keeps stale (potentially vulnerable) images
in scope for scanners and attackers who reach the registry.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_ecr_lifecycle_policy" "example" {
  repository = aws_ecr_repository.example.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Expire untagged images after 30 days"
      selection = {
        tagStatus   = "untagged"
        countType   = "sinceImagePushed"
        countUnit   = "days"
        countNumber = 30
      }
      action = { type = "expire" }
    }]
  })
}
```

## Verification

```sh
`aws ecr describe-lifecycle-policy --repository-name <name>` must return
a non-empty policy. Re-run tf-analyze in mode:verify-fixed.
```

## References

**Source**
  - [`catalog/SEC-AWS-ECR-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-ECR-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-ECR-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-ECR-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-ECR-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
