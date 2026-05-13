---
title: "SEC-GCP-IAP-001 — GCP backend service missing Identity-Aware Proxy (IAP)"
description: "tf-analyze rule SEC-GCP-IAP-001 (MEDIUM · security): GCP backend service missing Identity-Aware Proxy (IAP)"
keywords: "security, medium, terraform, iac, gcp, mitre-T1190, cwe-284, d3-uac, nist-csf-pr.ac-3, nist-800-53-ac-3"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-IAP-001 \u2014 GCP backend service missing Identity-Aware Proxy (IAP)",
  "description": "Enable IAP on the backend service and provision the OAuth client:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-IAP-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-IAP-001/"
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
  "keywords": "security, medium, terraform, MITRE T1190, CWE-284, D3-UAC",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-GCP-IAP-001 — GCP backend service missing Identity-Aware Proxy (IAP)

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-IAP-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-IAP-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-IAP-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP backend service missing Identity-Aware Proxy (IAP).** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_compute_backend_service` (`iap`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_compute_backend_service` has no `iap` block. Without
Identity-Aware Proxy, the backend is reachable by any client that
can hit the public LB IP. IAP enforces Google sign-in + IAM
authorization at the edge — equivalent to AWS ALB + Cognito user
pool (SEC-AWS-COGNITO-001) or Front Door + Entra ID auth.

## Why it likely fired

`google_compute_backend_service` has no `iap` block. Without
Identity-Aware Proxy, the backend is reachable by any client that
can hit the public LB IP. IAP enforces Google sign-in + IAM
authorization at the edge — equivalent to AWS ALB + Cognito user
pool (SEC-AWS-COGNITO-001) or Front Door + Entra ID auth.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-IAP-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable IAP on the backend service and provision the OAuth client:

    resource "google_compute_backend_service" "main" {
      # ...
      iap {
        enabled              = true
        oauth2_client_id     = google_iap_client.main.client_id
        oauth2_client_secret = google_iap_client.main.secret
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_compute_backend_service" "example" {
  name                  = "example"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  iap {
    enabled              = true
    oauth2_client_id     = google_iap_client.example.client_id
    oauth2_client_secret = google_iap_client.example.secret
  }
}
```

## Verification

```sh
`gcloud compute backend-services describe <name> --global \
  --format='value(iap.enabled)'` must return `True`.
```

## References

**PCI-DSS**
  - `Req-7.1`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**MITRE D3FEND**
  - [`D3-UAC`](https://d3fend.mitre.org/technique/D3-UAC/)

**NIST CSF 2.0**
  - [`PR.AC-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-3)

**Source**
  - [`catalog/SEC-GCP-IAP-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-IAP-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-IAP-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-IAP-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-IAP-001
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
