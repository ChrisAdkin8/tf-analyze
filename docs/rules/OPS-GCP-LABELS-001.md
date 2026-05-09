---
title: "OPS-GCP-LABELS-001 — GCP resource missing labels block"
description: "tf-analyze rule OPS-GCP-LABELS-001 (MEDIUM · ops): GCP resource missing labels block"
keywords: "ops, medium, terraform, iac, gcp"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "OPS-GCP-LABELS-001 \u2014 GCP resource missing labels block",
  "description": "Add a `labels` (or equivalent) block to every GCP resource that supports\nit. At minimum include `environment` and `managed_by = \"terraform\"`.\nLabels are required for cost allocation, compliance dashboards, and\nautomated cleanup policies. Us",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/OPS-GCP-LABELS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/OPS-GCP-LABELS-001/"
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
  "keywords": "ops, medium, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "ops",
  "isAccessibleForFree": true
}
</script>

# 💡 OPS-GCP-LABELS-001 — GCP resource missing labels block

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: ops](https://img.shields.io/badge/section-ops-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/OPS-GCP-LABELS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=OPS-GCP-LABELS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add OPS-GCP-LABELS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP resource missing labels block.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_compute_instance` (`labels`) — _the resource is missing a required attribute (or nested attribute path)._
2. **`resource_missing_arg`** on `google_storage_bucket` (`labels`) — _the resource is missing a required attribute (or nested attribute path)._
3. **`resource_missing_arg`** on `google_sql_database_instance` (`settings.user_labels`) — _the resource is missing a required attribute (or nested attribute path)._
4. **`resource_missing_arg`** on `google_container_cluster` (`resource_labels`) — _the resource is missing a required attribute (or nested attribute path)._
5. **`resource_missing_arg`** on `google_compute_disk` (`labels`) — _the resource is missing a required attribute (or nested attribute path)._
6. **`resource_missing_arg`** on `google_pubsub_topic` (`labels`) — _the resource is missing a required attribute (or nested attribute path)._
7. **`resource_missing_arg`** on `google_cloud_run_service` (`metadata.labels`) — _the resource is missing a required attribute (or nested attribute path)._
8. **`resource_missing_arg`** on `google_bigquery_dataset` (`labels`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain OPS-GCP-LABELS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `labels` (or equivalent) block to every GCP resource that supports
it. At minimum include `environment` and `managed_by = "terraform"`.
Labels are required for cost allocation, compliance dashboards, and
automated cleanup policies. Use a shared `locals` block or variable to
keep labels consistent across the module.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_compute_instance" "example" {
  # ... other arguments ...
  labels = {
    environment = "prod"
    owner       = "platform-team"
    project     = "my-project"
  }
}
```

## Verification

Run `tf-analyze` in mode:verify-fixed and confirm OPS-LABELS-001 is
RESOLVED. Or run `gcloud asset search-all-resources --query="NOT labels:environment"`
to find unlabeled resources in the project.

## References

**Source**
  - [`catalog/OPS-GCP-LABELS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/OPS-GCP-LABELS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain OPS-GCP-LABELS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore OPS-GCP-LABELS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - OPS-GCP-LABELS-001
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
