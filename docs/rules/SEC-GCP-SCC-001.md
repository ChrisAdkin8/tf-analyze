---
title: "SEC-GCP-SCC-001 — GCP Security Command Center notification not configured"
description: "tf-analyze rule SEC-GCP-SCC-001 (HIGH · security): GCP Security Command Center notification not configured"
keywords: "security, high, terraform, iac, gcp, cis-2.1, mitre-T1078, cwe-778, d3-nta, nist-csf-de.cm-1, nist-csf-de.cm-7, nist-800-53-si-4, nist-800-53-ra-5, csa-ccm-tvm-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-SCC-001 \u2014 GCP Security Command Center notification not configured",
  "description": "Wire SCC findings to a Pub/Sub topic so alerting platforms can react:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-SCC-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-SCC-001/"
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
  "keywords": "security, high, terraform, CIS 2.1, MITRE T1078, CWE-778, D3-NTA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-GCP-SCC-001 — GCP Security Command Center notification not configured

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-SCC-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-SCC-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-SCC-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Security Command Center notification not configured.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_absent`** on `google_scc_notification_config` — _the corpus is missing a resource type we expected to find given other resources present._
  No `google_scc_notification_config` declared. Security Command
Center detects misconfigurations (Security Health Analytics),
vulnerabilities (Web Security Scanner), and threats (Event Threat
Detection / Container Threat Detection). Without a notification
config piping findings to Pub/Sub, alerts stay buried in the SCC
console and no automated response is possible. This is the GCP
equivalent of `aws_guardduty_detector` (SEC-AWS-GUARDDUTY-001).

## Why it likely fired

No `google_scc_notification_config` declared. Security Command
Center detects misconfigurations (Security Health Analytics),
vulnerabilities (Web Security Scanner), and threats (Event Threat
Detection / Container Threat Detection). Without a notification
config piping findings to Pub/Sub, alerts stay buried in the SCC
console and no automated response is possible. This is the GCP
equivalent of `aws_guardduty_detector` (SEC-AWS-GUARDDUTY-001).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-SCC-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Wire SCC findings to a Pub/Sub topic so alerting platforms can react:

    resource "google_pubsub_topic" "scc" {
      name = "scc-findings"
    }

    resource "google_scc_notification_config" "high_severity" {
      config_id    = "high-severity"
      organization = var.org_id
      pubsub_topic = google_pubsub_topic.scc.id

      streaming_config {
        filter = "severity = \"HIGH\" OR severity = \"CRITICAL\""
      }
    }

Pair with `google_project_service` enabling
`securitycenter.googleapis.com` and `containerthreatdetection.googleapis.com`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_scc_notification_config" "all_findings" {
  config_id    = "all-findings"
  organization = var.org_id
  pubsub_topic = google_pubsub_topic.scc.id

  streaming_config {
    filter = "state = \"ACTIVE\""
  }
}
```

_Activating SCC Premium incurs per-asset cost; review pricing before deploying organisation-wide._

## Verification

```sh
`gcloud scc notifications list --organization=<org-id>` must return at
least one configuration, and the Pub/Sub topic must have a downstream
subscriber.
```

## References

**CIS Benchmark**
  - `CIS 2.1`

**PCI-DSS**
  - `Req-10.6`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1078`](https://attack.mitre.org/techniques/T1078/)

**CWE**
  - [`CWE-778`](https://cwe.mitre.org/data/definitions/778.html)

**MITRE D3FEND**
  - [`D3-NTA`](https://d3fend.mitre.org/technique/D3-NTA/)

**NIST CSF 2.0**
  - [`DE.CM-1`](https://www.nist.gov/cyberframework)
  - [`DE.CM-7`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SI-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=si-4)
  - [`RA-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ra-5)

**CSA CCM v4**
  - [`TVM-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-SCC-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-SCC-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-SCC-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-SCC-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-SCC-001
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
