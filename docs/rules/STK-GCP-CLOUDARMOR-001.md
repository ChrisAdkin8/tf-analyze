---
title: "STK-GCP-CLOUDARMOR-001 — GCP Cloud Armor security policy missing rate-based rule"
description: "tf-analyze rule STK-GCP-CLOUDARMOR-001 (MEDIUM · stack): GCP Cloud Armor security policy missing rate-based rule"
keywords: "stack, medium, terraform, iac, gcp, mitre-T1498, mitre-T1190, cwe-770, cwe-799, d3-waf, nist-csf-pr.pt-4, nist-800-53-sc-5, nist-800-53-si-4, csa-ccm-ais-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-CLOUDARMOR-001 \u2014 GCP Cloud Armor security policy missing rate-based rule",
  "description": "Add a rate-based ban rule near the top of the policy:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-CLOUDARMOR-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-CLOUDARMOR-001/"
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
  "keywords": "stack, medium, terraform, MITRE T1498, MITRE T1190, CWE-770, CWE-799, D3-WAF",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-GCP-CLOUDARMOR-001 — GCP Cloud Armor security policy missing rate-based rule

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-CLOUDARMOR-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-CLOUDARMOR-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-CLOUDARMOR-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Cloud Armor security policy missing rate-based rule.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_compute_security_policy` (`rule`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_compute_security_policy` has no rules — equivalent to
having no WAF attached. Defaults to allow-all.
2. **`resource_body_contains`** on `google_compute_security_policy` matching `/action\s*=\s*"allow"\s*\n?\s*priority\s*=\s*2147483647/` — _the resource body matches a regex inside the block._
  Policy only has the default `allow` rule at priority 2147483647 —
every layer-7 attack (credential stuffing, scraping, basic DDoS)
reaches the origin. Equivalent to SEC-AWS-WAF-002 (ALB+WAF without
rate-based rule).

## Why it likely fired

`google_compute_security_policy` has no rules — equivalent to
having no WAF attached. Defaults to allow-all.

Policy only has the default `allow` rule at priority 2147483647 —
every layer-7 attack (credential stuffing, scraping, basic DDoS)
reaches the origin. Equivalent to SEC-AWS-WAF-002 (ALB+WAF without
rate-based rule).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-CLOUDARMOR-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a rate-based ban rule near the top of the policy:

    resource "google_compute_security_policy" "main" {
      name = "edge-policy"

      rule {
        action   = "throttle"
        priority = 1000
        match {
          versioned_expr = "SRC_IPS_V1"
          config { src_ip_ranges = ["*"] }
        }
        rate_limit_options {
          conform_action = "allow"
          exceed_action  = "deny(429)"
          enforce_on_key = "IP"
          rate_limit_threshold {
            count        = 100
            interval_sec = 60
          }
        }
      }

      rule {
        action   = "allow"
        priority = 2147483647
        match {
          versioned_expr = "SRC_IPS_V1"
          config { src_ip_ranges = ["*"] }
        }
        description = "Default rule, higher priority overrides it"
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_compute_security_policy" "example" {
  name = "example"

  rule {
    action   = "throttle"
    priority = 1000
    match {
      versioned_expr = "SRC_IPS_V1"
      config { src_ip_ranges = ["*"] }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
    }
  }
}
```

_Rate-based rules may throttle legitimate burst traffic; tune the threshold against historical p99 RPS before promoting to production._

## Verification

```sh
`gcloud compute security-policies describe <name> --format=json | \
  jq '.rules[] | select(.rateLimitOptions != null)'` must return at
least one rate-based rule.
```

## References

**PCI-DSS**
  - `Req-6.6`

**SOC 2 Trust Services Criteria**
  - `CC6.6`

**MITRE ATT&CK**
  - [`T1498`](https://attack.mitre.org/techniques/T1498/)
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)

**CWE**
  - [`CWE-770`](https://cwe.mitre.org/data/definitions/770.html)
  - [`CWE-799`](https://cwe.mitre.org/data/definitions/799.html)

**MITRE D3FEND**
  - [`D3-WAF`](https://d3fend.mitre.org/technique/D3-WAF/)

**NIST CSF 2.0**
  - [`PR.PT-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-5)
  - [`SI-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=si-4)

**CSA CCM v4**
  - [`AIS-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/STK-GCP-CLOUDARMOR-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-CLOUDARMOR-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-CLOUDARMOR-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-CLOUDARMOR-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-CLOUDARMOR-001
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
