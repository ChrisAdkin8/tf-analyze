---
title: "STK-GCP-DATAPROC-001 — GCP Dataproc cluster missing autoscaling policy"
description: "tf-analyze rule STK-GCP-DATAPROC-001 (LOW · stack): GCP Dataproc cluster missing autoscaling policy"
keywords: "stack, low, terraform, iac, gcp, mitre-T1496, nist-csf-pr.pt-1"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-DATAPROC-001 \u2014 GCP Dataproc cluster missing autoscaling policy",
  "description": "Attach an autoscaling policy:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-DATAPROC-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-DATAPROC-001/"
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

# ℹ️ STK-GCP-DATAPROC-001 — GCP Dataproc cluster missing autoscaling policy

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-DATAPROC-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-DATAPROC-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-DATAPROC-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Dataproc cluster missing autoscaling policy.** This rule has `default_urgency: LOW` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_dataproc_cluster` (`cluster_config.autoscaling_config.policy_uri`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_dataproc_cluster` has no `cluster_config.autoscaling_config`.
Worker count is fixed; idle clusters pay for unused capacity, busy
ones miss elastic burst.

## Why it likely fired

`google_dataproc_cluster` has no `cluster_config.autoscaling_config`.
Worker count is fixed; idle clusters pay for unused capacity, busy
ones miss elastic burst.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-DATAPROC-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Attach an autoscaling policy:

    resource "google_dataproc_autoscaling_policy" "main" {
      policy_id = "main"
      worker_config { max_instances = 10 }
      secondary_worker_config { max_instances = 50 }
    }

    resource "google_dataproc_cluster" "main" {
      # ...
      cluster_config {
        autoscaling_config {
          policy_uri = google_dataproc_autoscaling_policy.main.id
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_dataproc_cluster" "example" {
  name   = "example"
  region = "us-central1"
  cluster_config {
    autoscaling_config {
      policy_uri = google_dataproc_autoscaling_policy.example.id
    }
  }
}
```

## Verification

```sh
`gcloud dataproc clusters describe <name> --region <r> --format='value(config.autoscalingConfig.policyUri)'`
must be non-empty.
```

## References

**MITRE ATT&CK**
  - [`T1496`](https://attack.mitre.org/techniques/T1496/)

**NIST CSF 2.0**
  - [`PR.PT-1`](https://www.nist.gov/cyberframework)

**Source**
  - [`catalog/STK-GCP-DATAPROC-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-DATAPROC-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-DATAPROC-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-DATAPROC-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-DATAPROC-001
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
