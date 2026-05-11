---
title: "SEC-AWS-LB-LISTENER-002 — Load balancer HTTPS listener allows TLS < 1.2"
description: "tf-analyze rule SEC-AWS-LB-LISTENER-002 (HIGH · security): Load balancer HTTPS listener allows TLS < 1.2"
keywords: "security, high, terraform, iac, aws, mitre-T1565.001, cwe-326, cwe-327, nist-csf-pr.ds-2, nist-800-53-sc-8, nist-800-53-sc-8-1, nist-800-53-sc-13, csa-ccm-ekm-04, csa-ccm-dsi-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-LB-LISTENER-002 \u2014 Load balancer HTTPS listener allows TLS < 1.2",
  "description": "resource \"aws_lb_listener\" \"https\" {\n  load_balancer_arn = aws_lb.app.arn\n  port              = 443\n  protocol          = \"HTTPS\"\n  ssl_policy        = \"ELBSecurityPolicy-TLS13-1-2-2021-06\"\n  # ...\n}",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-LB-LISTENER-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-LB-LISTENER-002/"
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
  "keywords": "security, high, terraform, MITRE T1565.001, CWE-326, CWE-327",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-LB-LISTENER-002 — Load balancer HTTPS listener allows TLS < 1.2

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-LB-LISTENER-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-LB-LISTENER-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-LB-LISTENER-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Load balancer HTTPS listener allows TLS < 1.2.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_arg`** on `aws_lb_listener` (`ssl_policy`) matching `/^(?:ELBSecurityPolicy-2016-08|ELBSecurityPolicy-FS-2018-06|ELBSecurityPolicy-TLS-1-(?:0|1)-2017-01)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  ssl_policy values that pre-date the TLS-1.2-floor era (the 2016
and TLS-1-0/1-1 policies) accept TLS 1.0 / 1.1 connections —
both deprecated and broken by PCI-DSS 4.0 and most modern
regulators. The 2019 + 2021 policy generations require TLS 1.2;
`ELBSecurityPolicy-TLS13-1-2-2021-06` adds 1.3 support.

## Why it likely fired

ssl_policy values that pre-date the TLS-1.2-floor era (the 2016
and TLS-1-0/1-1 policies) accept TLS 1.0 / 1.1 connections —
both deprecated and broken by PCI-DSS 4.0 and most modern
regulators. The 2019 + 2021 policy generations require TLS 1.2;
`ELBSecurityPolicy-TLS13-1-2-2021-06` adds 1.3 support.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-LB-LISTENER-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  # ...
}

Pair with a redirect on the HTTP (`port = 80`) listener so plain
HTTP can't reach the backend at all.

## Verification

```sh
`aws elbv2 describe-listeners --load-balancer-arn <arn> --query 'Listeners[?Protocol==`HTTPS`].SslPolicy'`
Confirm each listed policy contains `TLS13-1-2` or `TLS-1-2-Ext`.
```

## References

**MITRE ATT&CK**
  - [`T1565.001`](https://attack.mitre.org/techniques/T1565/001/)

**CWE**
  - [`CWE-326`](https://cwe.mitre.org/data/definitions/326.html)
  - [`CWE-327`](https://cwe.mitre.org/data/definitions/327.html)

**NIST CSF 2.0**
  - [`PR.DS-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-8`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-8)
  - [`SC-8(1)`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-8-1)
  - [`SC-13`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-13)

**CSA CCM v4**
  - [`EKM-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
  - [`DSI-03`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**OWASP (namespaced)**
  - `A02`

**Source**
  - [`catalog/SEC-AWS-LB-LISTENER-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-LB-LISTENER-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-AWS-LB-LISTENER-*` family:

- [`SEC-AWS-LB-LISTENER-001`](./SEC-AWS-LB-LISTENER-001.md) — ALB listener serves plain HTTP without redirect

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-LB-LISTENER-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-LB-LISTENER-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-LB-LISTENER-002
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
