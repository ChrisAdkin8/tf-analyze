---
title: "SEC-GCP-COMPUTE-PUBLIC-IP-001 — Compute instance has a public IP via access_config"
description: "tf-analyze rule SEC-GCP-COMPUTE-PUBLIC-IP-001 (HIGH · security): Compute instance has a public IP via access_config"
keywords: "security, high, terraform, iac, gcp, cis-4.9, mitre-T1190, cwe-284, d3-iaa"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-COMPUTE-PUBLIC-IP-001 \u2014 Compute instance has a public IP via access_config",
  "description": "Remove the `access_config {}` block:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-COMPUTE-PUBLIC-IP-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-COMPUTE-PUBLIC-IP-001/"
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
  "keywords": "security, high, terraform, CIS 4.9, MITRE T1190, CWE-284, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-GCP-COMPUTE-PUBLIC-IP-001 — Compute instance has a public IP via access_config

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-COMPUTE-PUBLIC-IP-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-COMPUTE-PUBLIC-IP-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-COMPUTE-PUBLIC-IP-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Compute instance has a public IP via access_config.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_body_contains`** on `google_compute_instance` matching `/access_config\s*\{/` — _the resource body matches a regex inside the block._
  A `google_compute_instance` body contains an `access_config {}`
sub-block (always inside `network_interface`). Even an empty
`access_config` block requests an ephemeral public IP, exposing
the VM directly to the internet.

## Why it likely fired

A `google_compute_instance` body contains an `access_config {}`
sub-block (always inside `network_interface`). Even an empty
`access_config` block requests an ephemeral public IP, exposing
the VM directly to the internet.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-COMPUTE-PUBLIC-IP-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove the `access_config {}` block:

    network_interface {
      network    = google_compute_network.app.id
      subnetwork = google_compute_subnetwork.app.id
      # No access_config => no public IP
    }

If outbound internet access is needed for package fetches or API
calls, use a Cloud NAT gateway on the VPC. If inbound access is
needed (rare), put the VM behind an Identity-Aware Proxy or HTTPS
load balancer rather than exposing the instance directly.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_compute_instance" "example" {
  name         = "example"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  boot_disk {
    initialize_params { image = "debian-cloud/debian-11" }
  }
  network_interface {
    network    = google_compute_network.vpc.id
    subnetwork = google_compute_subnetwork.private.id
    # No access_config block — no public IP assigned
  }
}
```

## Verification

After applying, run:

    gcloud compute instances describe <name> --zone=<zone> \\
      --format='value(networkInterfaces[0].accessConfigs)'

This should print nothing. Re-run tf-analyze to confirm clean.

## References

**CIS Benchmark**
  - `CIS 4.9`

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**MITRE D3FEND**
  - [`D3-IAA`](https://d3fend.mitre.org/technique/D3-IAA/)

**Related rules**
  - [`SEC-NETWORK-001`](./SEC-NETWORK-001.md)

**Source**
  - [`catalog/SEC-GCP-COMPUTE-PUBLIC-IP-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-COMPUTE-PUBLIC-IP-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-COMPUTE-PUBLIC-IP-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-COMPUTE-PUBLIC-IP-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-COMPUTE-PUBLIC-IP-001
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
