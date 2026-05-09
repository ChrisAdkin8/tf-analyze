# ⚠️ SEC-AWS-LB-LISTENER-001 — ALB listener serves plain HTTP without redirect

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **ALB listener serves plain HTTP without redirect.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_lb_listener` (`protocol`) matching `/^HTTP$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_lb_listener` has `protocol = "HTTP"`. Serving traffic over plain HTTP
exposes session tokens, credentials, and application data to network eavesdroppers.
Every HTTP listener should redirect to HTTPS; only the HTTPS listener should
serve application traffic.

## Why it likely fired

`aws_lb_listener` has `protocol = "HTTP"`. Serving traffic over plain HTTP
exposes session tokens, credentials, and application data to network eavesdroppers.
Every HTTP listener should redirect to HTTPS; only the HTTPS listener should
serve application traffic.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-LB-LISTENER-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Either switch the listener to HTTPS or add a redirect action:

    # Option A — HTTPS listener
    resource "aws_lb_listener" "https" {
      load_balancer_arn = aws_lb.main.arn
      port              = "443"
      protocol          = "HTTPS"
      ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
      certificate_arn   = aws_acm_certificate.cert.arn
      default_action {
        type             = "forward"
        target_group_arn = aws_lb_target_group.app.arn
      }
    }

    # Option B — HTTP→HTTPS redirect
    resource "aws_lb_listener" "http_redirect" {
      load_balancer_arn = aws_lb.main.arn
      port              = "80"
      protocol          = "HTTP"
      default_action {
        type = "redirect"
        redirect {
          port        = "443"
          protocol    = "HTTPS"
          status_code = "HTTP_301"
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.example.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
```

## Verification

```sh
`aws elbv2 describe-listeners --load-balancer-arn <arn> \
  --query 'Listeners[?Protocol==\`HTTP\`].DefaultActions[*].Type'`
must return `["redirect"]`, not `["forward"]`.
```

## References

**CIS Benchmark**
  - `CIS 2.1` — Ensure all HTTP traffic is redirected to HTTPS

**PCI-DSS**
  - `Req-4.1`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1071.001`](https://attack.mitre.org/techniques/T1071/001/)

**Source**
  - [`catalog/SEC-AWS-LB-LISTENER-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-LB-LISTENER-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-LB-LISTENER-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-LB-LISTENER-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-LB-LISTENER-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
