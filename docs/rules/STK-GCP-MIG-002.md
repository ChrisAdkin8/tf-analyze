---
title: "STK-GCP-MIG-002 — GCP managed instance group missing autoscaler"
description: "tf-analyze rule STK-GCP-MIG-002 (LOW · stack): GCP managed instance group missing autoscaler"
keywords: "stack, low, terraform, iac, gcp, mitre-T1496, nist-csf-pr.pt-1"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-MIG-002 \u2014 GCP managed instance group missing autoscaler",
  "description": "Bind an autoscaler with sensible CPU / load-balancing utilization\ntargets:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-MIG-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-MIG-002/"
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
  "keywords": "stack, low, terraform, MITRE T1496",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ℹ️ STK-GCP-MIG-002 — GCP managed instance group missing autoscaler

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-MIG-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-MIG-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-MIG-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP managed instance group missing autoscaler.** This rule has `default_urgency: LOW` and operates on a single resource blast radius. 

## What this checks

1. **`resource_absent`** on `google_compute_autoscaler` — _the corpus is missing a resource type we expected to find given other resources present._
  `google_compute_instance_group_manager` exists but no
`google_compute_autoscaler` is bound to it. Capacity is fixed —
idle hours waste compute, busy hours fail under load.

## Why it likely fired

`google_compute_instance_group_manager` exists but no
`google_compute_autoscaler` is bound to it. Capacity is fixed —
idle hours waste compute, busy hours fail under load.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-MIG-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Bind an autoscaler with sensible CPU / load-balancing utilization
targets:

    resource "google_compute_autoscaler" "main" {
      name   = "main-asg"
      zone   = "us-central1-a"
      target = google_compute_instance_group_manager.main.id
      autoscaling_policy {
        min_replicas    = 2
        max_replicas    = 20
        cooldown_period = 60
        cpu_utilization {
          target = 0.6
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_compute_autoscaler" "example" {
  name   = "example"
  zone   = "us-central1-a"
  target = google_compute_instance_group_manager.example.id
  autoscaling_policy {
    min_replicas    = 2
    max_replicas    = 20
    cooldown_period = 60
    cpu_utilization {
      target = 0.6
    }
  }
}
```

## Verification

```sh
`gcloud compute instance-groups managed describe <name> --zone <z> \
  --format='value(status.autoscaler)'` must return a non-empty value.
```

## References

**MITRE ATT&CK**
  - [`T1496`](https://attack.mitre.org/techniques/T1496/)

**NIST CSF 2.0**
  - [`PR.PT-1`](https://www.nist.gov/cyberframework)

**Source**
  - [`catalog/STK-GCP-MIG-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-MIG-002.yaml) — canonical YAML

## Family

See also rules in the `STK-GCP-MIG-*` family:

- [`STK-GCP-MIG-001`](./STK-GCP-MIG-001.md) — GCP managed instance group missing auto-healing

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-MIG-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-MIG-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-MIG-002
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
