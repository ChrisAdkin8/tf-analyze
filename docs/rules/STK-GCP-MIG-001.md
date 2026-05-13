---
title: "STK-GCP-MIG-001 — GCP managed instance group missing auto-healing"
description: "tf-analyze rule STK-GCP-MIG-001 (MEDIUM · stack): GCP managed instance group missing auto-healing"
keywords: "stack, medium, terraform, iac, gcp, mitre-T1485, nist-csf-pr.ip-1, nist-800-53-cp-10"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-MIG-001 \u2014 GCP managed instance group missing auto-healing",
  "description": "Attach a health check and configure auto-healing:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-MIG-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-MIG-001/"
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
  "keywords": "stack, medium, terraform, MITRE T1485",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-GCP-MIG-001 — GCP managed instance group missing auto-healing

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-MIG-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-MIG-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-MIG-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP managed instance group missing auto-healing.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_compute_instance_group_manager` (`auto_healing_policies`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_compute_instance_group_manager` has no
`auto_healing_policies`. Unhealthy VMs (failed health checks, hung
instances) are not automatically replaced — capacity silently
drops below the requested target.

## Why it likely fired

`google_compute_instance_group_manager` has no
`auto_healing_policies`. Unhealthy VMs (failed health checks, hung
instances) are not automatically replaced — capacity silently
drops below the requested target.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-MIG-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Attach a health check and configure auto-healing:

    resource "google_compute_health_check" "main" {
      name = "main-hc"
      http_health_check { port = 80 }
    }

    resource "google_compute_instance_group_manager" "main" {
      # ...
      auto_healing_policies {
        health_check      = google_compute_health_check.main.id
        initial_delay_sec = 300
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_compute_instance_group_manager" "example" {
  name               = "example"
  base_instance_name = "example"
  zone               = "us-central1-a"
  target_size        = 3

  version {
    instance_template = google_compute_instance_template.example.id
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.example.id
    initial_delay_sec = 300
  }
}
```

## Verification

```sh
`gcloud compute instance-groups managed describe <name> --zone <z> \
  --format='value(autoHealingPolicies.healthCheck)'` must return a
non-empty health-check URL.
```

## References

**MITRE ATT&CK**
  - [`T1485`](https://attack.mitre.org/techniques/T1485/)

**NIST CSF 2.0**
  - [`PR.IP-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CP-10`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cp-10)

**Source**
  - [`catalog/STK-GCP-MIG-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-MIG-001.yaml) — canonical YAML

## Family

See also rules in the `STK-GCP-MIG-*` family:

- [`STK-GCP-MIG-002`](./STK-GCP-MIG-002.md) — GCP managed instance group missing autoscaler

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-MIG-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-MIG-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-MIG-001
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
