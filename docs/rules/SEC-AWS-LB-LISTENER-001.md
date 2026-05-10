---
title: "SEC-AWS-LB-LISTENER-001 — ALB listener serves plain HTTP without redirect"
description: "tf-analyze rule SEC-AWS-LB-LISTENER-001 (HIGH · security): ALB listener serves plain HTTP without redirect"
keywords: "security, high, terraform, iac, aws, cis-{'id': '2.1', 'title': 'Ensure all HTTP traffic is redirected to HTTPS'}, mitre-T1071.001, cwe-319, d3-ei"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-LB-LISTENER-001 \u2014 ALB listener serves plain HTTP without redirect",
  "description": "Either switch the listener to HTTPS or add a redirect action:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-LB-LISTENER-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-LB-LISTENER-001/"
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
  "keywords": "security, high, terraform, CIS {'id': '2.1', 'title': 'Ensure all HTTP traffic is redirected to HTTPS'}, MITRE T1071.001, CWE-319, D3-EI",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-LB-LISTENER-001 — ALB listener serves plain HTTP without redirect

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-LB-LISTENER-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-LB-LISTENER-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-LB-LISTENER-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

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

**CWE**
  - [`CWE-319`](https://cwe.mitre.org/data/definitions/319.html)

**MITRE D3FEND**
  - [`D3-EI`](https://d3fend.mitre.org/technique/D3-EI/)

**Source**
  - [`catalog/SEC-AWS-LB-LISTENER-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-LB-LISTENER-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-AWS-LB-LISTENER-*` family:

- [`SEC-AWS-LB-LISTENER-002`](./SEC-AWS-LB-LISTENER-002.md) — Load balancer HTTPS listener allows TLS < 1.2

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
