---
title: "SEC-GCP-COMPUTE-OSLOGIN-001 — GCP Compute instance has OS Login disabled"
description: "tf-analyze rule SEC-GCP-COMPUTE-OSLOGIN-001 (MEDIUM · security): GCP Compute instance has OS Login disabled"
keywords: "security, medium, terraform, iac, gcp, cis-4.1, mitre-T1078, cwe-287, d3-uac, nist-csf-pr.ac-1, nist-800-53-ac-2, csa-ccm-iam-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-COMPUTE-OSLOGIN-001 \u2014 GCP Compute instance has OS Login disabled",
  "description": "Enable OS Login on every Compute instance (or set it project-wide via\n`google_compute_project_metadata`):",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-COMPUTE-OSLOGIN-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-COMPUTE-OSLOGIN-001/"
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
  "keywords": "security, medium, terraform, CIS 4.1, MITRE T1078, CWE-287, D3-UAC",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-GCP-COMPUTE-OSLOGIN-001 — GCP Compute instance has OS Login disabled

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-COMPUTE-OSLOGIN-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-COMPUTE-OSLOGIN-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-COMPUTE-OSLOGIN-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Compute instance has OS Login disabled.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_body_contains`** on `google_compute_instance` matching `/enable-oslogin\s*=\s*"FALSE"/` — _the resource body matches a regex inside the block._
  `google_compute_instance.metadata.enable-oslogin = "FALSE"` falls
back to project-wide SSH keys (or local `ssh-keys` metadata),
which can't be governed by IAM. Centralised SSH governance via
OS Login is bypassed.

## Why it likely fired

`google_compute_instance.metadata.enable-oslogin = "FALSE"` falls
back to project-wide SSH keys (or local `ssh-keys` metadata),
which can't be governed by IAM. Centralised SSH governance via
OS Login is bypassed.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-COMPUTE-OSLOGIN-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable OS Login on every Compute instance (or set it project-wide via
`google_compute_project_metadata`):

    resource "google_compute_instance" "main" {
      # ...
      metadata = {
        enable-oslogin = "TRUE"
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_compute_instance" "example" {
  name         = "example"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  boot_disk { initialize_params { image = "debian-cloud/debian-12" } }
  network_interface { network = "default" }
  metadata = {
    enable-oslogin = "TRUE"
  }
}
```

## Verification

```sh
`gcloud compute instances describe <name> --zone <zone> \
  --format='value(metadata.items.filter(key="enable-oslogin"))'` must
return `TRUE`.
```

## References

**CIS Benchmark**
  - `CIS 4.1`

**SOC 2 Trust Services Criteria**
  - `CC6.3`

**MITRE ATT&CK**
  - [`T1078`](https://attack.mitre.org/techniques/T1078/)

**CWE**
  - [`CWE-287`](https://cwe.mitre.org/data/definitions/287.html)

**MITRE D3FEND**
  - [`D3-UAC`](https://d3fend.mitre.org/technique/D3-UAC/)

**NIST CSF 2.0**
  - [`PR.AC-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-2`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-2)

**CSA CCM v4**
  - [`IAM-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-COMPUTE-OSLOGIN-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-COMPUTE-OSLOGIN-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-COMPUTE-OSLOGIN-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-COMPUTE-OSLOGIN-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-COMPUTE-OSLOGIN-001
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
