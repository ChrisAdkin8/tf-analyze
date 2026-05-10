---
title: "COST-GCP-RISK-001 — Expensive resource without cost control"
description: "tf-analyze rule COST-GCP-RISK-001 (MEDIUM · ops): Expensive resource without cost control"
keywords: "ops, medium, terraform, iac, gcp, mitre-T1496"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "COST-GCP-RISK-001 \u2014 Expensive resource without cost control",
  "description": "Add explicit cost controls to prevent bill surprises:\n- Spanner: set `processing_units` explicitly\n- GKE: set `cluster_autoscaling.resource_limits` with max bounds\n- Cloud SQL: set `settings.disk_autoresize_limit`\n- Compute: consider `sched",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/COST-GCP-RISK-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/COST-GCP-RISK-001/"
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
  "keywords": "ops, medium, terraform, MITRE T1496",
  "proficiencyLevel": "Expert",
  "articleSection": "ops",
  "isAccessibleForFree": true
}
</script>

# 💡 COST-GCP-RISK-001 — Expensive resource without cost control

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: ops](https://img.shields.io/badge/section-ops-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/COST-GCP-RISK-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=COST-GCP-RISK-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add COST-GCP-RISK-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Expensive resource without cost control.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_spanner_instance` (`processing_units`) — _the resource is missing a required attribute (or nested attribute path)._
  Spanner instance without explicit processing_units (defaults may be expensive)
2. **`resource_missing_arg`** on `google_container_cluster` (`cluster_autoscaling.resource_limits`) — _the resource is missing a required attribute (or nested attribute path)._
  GKE cluster without autoscaler resource_limits (unbounded scale-up)
3. **`resource_missing_arg`** on `google_sql_database_instance` (`settings.disk_autoresize_limit`) — _the resource is missing a required attribute (or nested attribute path)._
  Cloud SQL without disk_autoresize_limit (unbounded disk growth)
4. **`resource_missing_arg`** on `google_compute_instance` (`scheduling`) — _the resource is missing a required attribute (or nested attribute path)._
  Compute instance without scheduling block (always-on by default, consider preemptible for dev)

## Why it likely fired

Spanner instance without explicit processing_units (defaults may be expensive)

GKE cluster without autoscaler resource_limits (unbounded scale-up)

Cloud SQL without disk_autoresize_limit (unbounded disk growth)

Compute instance without scheduling block (always-on by default, consider preemptible for dev)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain COST-GCP-RISK-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add explicit cost controls to prevent bill surprises:
- Spanner: set `processing_units` explicitly
- GKE: set `cluster_autoscaling.resource_limits` with max bounds
- Cloud SQL: set `settings.disk_autoresize_limit`
- Compute: consider `scheduling { preemptible = true }` for non-production

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_spanner_instance" "app" {
  config           = "regional-us-central1"
  display_name     = "app"
  processing_units = 100
}

resource "google_sql_database_instance" "app" {
  settings {
    tier                   = "db-f1-micro"
    disk_autoresize        = true
    disk_autoresize_limit  = 50
  }
}
```

## Verification

Review `terraform plan` output to confirm the cost control arguments are
set. Check billing alerts are configured for the project.

## References

**MITRE ATT&CK**
  - [`T1496`](https://attack.mitre.org/techniques/T1496/)

**Source**
  - [`catalog/COST-GCP-RISK-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/COST-GCP-RISK-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain COST-GCP-RISK-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore COST-GCP-RISK-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - COST-GCP-RISK-001
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
