---
title: "SEC-GCP-FIREWALL-LOG-001 — GCP firewall rule missing log_config (denied traffic invisible)"
description: "tf-analyze rule SEC-GCP-FIREWALL-LOG-001 (MEDIUM · security): GCP firewall rule missing log_config (denied traffic invisible)"
keywords: "security, medium, terraform, iac, gcp, cis-3.7, mitre-T1562.008, cwe-778, d3-iaa, nist-csf-de.cm-1, nist-800-53-au-2, csa-ccm-log-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-FIREWALL-LOG-001 \u2014 GCP firewall rule missing log_config (denied traffic invisible)",
  "description": "Enable firewall logging on rules guarding sensitive services:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-FIREWALL-LOG-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-FIREWALL-LOG-001/"
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
  "keywords": "security, medium, terraform, CIS 3.7, MITRE T1562.008, CWE-778, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-GCP-FIREWALL-LOG-001 — GCP firewall rule missing log_config (denied traffic invisible)

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-FIREWALL-LOG-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-FIREWALL-LOG-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-FIREWALL-LOG-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP firewall rule missing log_config (denied traffic invisible).** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_compute_firewall` (`log_config`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_compute_firewall` has no `log_config` block. Denied and
allowed traffic on this rule is not logged to Cloud Logging,
blinding incident response and DDoS forensics.

## Why it likely fired

`google_compute_firewall` has no `log_config` block. Denied and
allowed traffic on this rule is not logged to Cloud Logging,
blinding incident response and DDoS forensics.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-FIREWALL-LOG-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable firewall logging on rules guarding sensitive services:

    resource "google_compute_firewall" "main" {
      # ...
      log_config {
        metadata = "INCLUDE_ALL_METADATA"
      }
    }

For very high-throughput rules consider `EXCLUDE_ALL_METADATA` to keep
log volume manageable.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_compute_firewall" "example" {
  name    = "allow-ssh"
  network = google_compute_network.main.name
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["10.0.0.0/8"]
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}
```

## Verification

```sh
`gcloud compute firewall-rules describe <name> --format='value(logConfig.enable)'`
must return `True`.
```

## References

**CIS Benchmark**
  - `CIS 3.7`

**PCI-DSS**
  - `Req-10.2`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1562.008`](https://attack.mitre.org/techniques/T1562/008/)

**CWE**
  - [`CWE-778`](https://cwe.mitre.org/data/definitions/778.html)

**MITRE D3FEND**
  - [`D3-IAA`](https://d3fend.mitre.org/technique/D3-IAA/)

**NIST CSF 2.0**
  - [`DE.CM-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AU-2`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-2)

**CSA CCM v4**
  - [`LOG-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-FIREWALL-LOG-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-FIREWALL-LOG-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-FIREWALL-LOG-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-FIREWALL-LOG-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-FIREWALL-LOG-001
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
