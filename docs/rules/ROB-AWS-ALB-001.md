# 💡 ROB-AWS-ALB-001 — Load balancer deletion protection disabled

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Load balancer deletion protection disabled.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_lb` (`enable_deletion_protection`) — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_lb` has `enable_deletion_protection = false` or the attribute is absent.
Without deletion protection the load balancer can be accidentally destroyed by
a `terraform destroy` or a mis-applied plan, taking all dependent services
offline immediately.
2. **`resource_arg`** on `aws_alb` (`enable_deletion_protection`) — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_alb` (legacy alias for `aws_lb`) has deletion protection disabled or absent.

## Why it likely fired

`aws_lb` has `enable_deletion_protection = false` or the attribute is absent.
Without deletion protection the load balancer can be accidentally destroyed by
a `terraform destroy` or a mis-applied plan, taking all dependent services
offline immediately.

`aws_alb` (legacy alias for `aws_lb`) has deletion protection disabled or absent.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-ALB-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `enable_deletion_protection = true` on every production load balancer:

    resource "aws_lb" "main" {
      name               = "main"
      internal           = false
      load_balancer_type = "application"

      enable_deletion_protection = true
    }

To remove the resource you must first set the flag to `false` and apply,
then destroy. This prevents accidental teardown.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_lb" "example" {
  name               = "example"
  load_balancer_type = "application"
  enable_deletion_protection = true
}
```

## Verification

```sh
`aws elbv2 describe-load-balancers --names <name> \
  --query 'LoadBalancers[*].DeletionProtection'`
must return `true`.
```

## References

**Source**
  - [`catalog/ROB-AWS-ALB-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-ALB-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-ALB-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-ALB-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-ALB-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
