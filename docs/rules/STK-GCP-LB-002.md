---
title: "STK-GCP-LB-002 — GCP HTTPS load balancer missing SSL policy (default permits TLS 1.0)"
description: "tf-analyze rule STK-GCP-LB-002 (HIGH · stack): GCP HTTPS load balancer missing SSL policy (default permits TLS 1.0)"
keywords: "stack, high, terraform, iac, gcp, cis-3.9, mitre-T1040, mitre-T1557, cwe-326, cwe-327, d3-et, nist-csf-pr.ds-2, nist-800-53-sc-8, nist-800-53-sc-13, csa-ccm-dsi-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-LB-002 \u2014 GCP HTTPS load balancer missing SSL policy (default permits TLS 1.0)",
  "description": "Attach a hardened SSL policy:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-LB-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-LB-002/"
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
  "keywords": "stack, high, terraform, CIS 3.9, MITRE T1040, MITRE T1557, CWE-326, CWE-327, D3-ET",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-GCP-LB-002 — GCP HTTPS load balancer missing SSL policy (default permits TLS 1.0)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-LB-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-LB-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-LB-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP HTTPS load balancer missing SSL policy (default permits TLS 1.0).** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_compute_target_https_proxy` (`ssl_policy`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_compute_target_https_proxy` has no `ssl_policy`. The
default GCP SSL policy (`COMPATIBLE`) permits TLS 1.0 and TLS 1.1,
which are deprecated by the IETF and forbidden by PCI-DSS v4.0
and FedRAMP-High. Equivalent to the AWS ALB TLS-1.0 finding
(SEC-AWS-LB-LISTENER-002).
2. **`resource_arg`** on `google_compute_ssl_policy` (`min_tls_version`) matching `/^TLS_1_(0|1)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `google_compute_ssl_policy.min_tls_version` permits TLS 1.0 or
TLS 1.1 — same risk class even when an explicit policy is
attached.
3. **`resource_arg`** on `google_compute_ssl_policy` (`profile`) matching `/^COMPATIBLE$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `google_compute_ssl_policy.profile = "COMPATIBLE"` is GCP's
loosest profile, allowing legacy cipher suites and TLS 1.0.

## Why it likely fired

`google_compute_target_https_proxy` has no `ssl_policy`. The
default GCP SSL policy (`COMPATIBLE`) permits TLS 1.0 and TLS 1.1,
which are deprecated by the IETF and forbidden by PCI-DSS v4.0
and FedRAMP-High. Equivalent to the AWS ALB TLS-1.0 finding
(SEC-AWS-LB-LISTENER-002).

`google_compute_ssl_policy.min_tls_version` permits TLS 1.0 or
TLS 1.1 — same risk class even when an explicit policy is
attached.

`google_compute_ssl_policy.profile = "COMPATIBLE"` is GCP's
loosest profile, allowing legacy cipher suites and TLS 1.0.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-LB-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Attach a hardened SSL policy:

    resource "google_compute_ssl_policy" "modern" {
      name            = "modern-tls"
      profile         = "MODERN"
      min_tls_version = "TLS_1_2"
    }

    resource "google_compute_target_https_proxy" "main" {
      # ...
      ssl_policy = google_compute_ssl_policy.modern.id
    }

Use `profile = "RESTRICTED"` for FedRAMP-High / PCI-DSS workloads.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_compute_ssl_policy" "modern" {
  name            = "modern-tls"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_target_https_proxy" "example" {
  name             = "example"
  url_map          = google_compute_url_map.example.id
  ssl_certificates = [google_compute_ssl_certificate.example.id]
  ssl_policy       = google_compute_ssl_policy.modern.id
}
```

_Tightening to TLS 1.2 breaks legacy clients (Win XP IE, embedded devices) that cannot negotiate TLS 1.2._

## Verification

```sh
`gcloud compute target-https-proxies describe <name> \
  --format='value(sslPolicy)'` must return a non-empty resource URL,
and the policy's `minTlsVersion` must be `TLS_1_2` or `TLS_1_3`.
```

## References

**CIS Benchmark**
  - `CIS 3.9`

**PCI-DSS**
  - `Req-4.1`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1040`](https://attack.mitre.org/techniques/T1040/)
  - [`T1557`](https://attack.mitre.org/techniques/T1557/)

**CWE**
  - [`CWE-326`](https://cwe.mitre.org/data/definitions/326.html)
  - [`CWE-327`](https://cwe.mitre.org/data/definitions/327.html)

**MITRE D3FEND**
  - [`D3-ET`](https://d3fend.mitre.org/technique/D3-ET/)

**NIST CSF 2.0**
  - [`PR.DS-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-8`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-8)
  - [`SC-13`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-13)

**CSA CCM v4**
  - [`DSI-03`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/STK-GCP-LB-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-LB-002.yaml) — canonical YAML

## Family

See also rules in the `STK-GCP-LB-*` family:

- [`STK-GCP-LB-001`](./STK-GCP-LB-001.md) — GCP load balancer backend service has logging disabled

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-LB-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-LB-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-LB-002
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
