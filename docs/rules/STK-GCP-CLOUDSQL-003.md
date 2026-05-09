---
title: "STK-GCP-CLOUDSQL-003 — Cloud SQL instance missing deletion protection"
description: "tf-analyze rule STK-GCP-CLOUDSQL-003 (HIGH · stack): Cloud SQL instance missing deletion protection"
keywords: "stack, high, terraform, iac, gcp, cis-6.6"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-CLOUDSQL-003 \u2014 Cloud SQL instance missing deletion protection",
  "description": "Set `deletion_protection = true` on every Cloud SQL instance. This is\nthe only safety net against `terraform destroy` removing a database\nwith all of its data.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-CLOUDSQL-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-CLOUDSQL-003/"
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
  "keywords": "stack, high, terraform, CIS 6.6",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-GCP-CLOUDSQL-003 — Cloud SQL instance missing deletion protection

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-CLOUDSQL-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-CLOUDSQL-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-CLOUDSQL-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Cloud SQL instance missing deletion protection.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_sql_database_instance` (`deletion_protection`) — _the resource is missing a required attribute (or nested attribute path)._
2. **`hcl_attr`** on `google_sql_database_instance` (`deletion_protection`) not equal to `True` — _an attribute value differs from the expected literal._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-CLOUDSQL-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `deletion_protection = true` on every Cloud SQL instance. This is
the only safety net against `terraform destroy` removing a database
with all of its data.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_sql_database_instance" "example" {
  name             = "example"
  database_version = "POSTGRES_15"
  deletion_protection = true
  settings {
    tier = "db-f1-micro"
  }
}
```

## Verification

```sh
`gcloud sql instances describe <name> --format='value(settings.deletionProtectionEnabled)'`
must return `True`.
```

## References

**CIS Benchmark**
  - `CIS 6.6`

**Source**
  - [`catalog/STK-GCP-CLOUDSQL-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-CLOUDSQL-003.yaml) — canonical YAML

## Family

See also rules in the `STK-GCP-CLOUDSQL-*` family:

- [`STK-GCP-CLOUDSQL-001`](./STK-GCP-CLOUDSQL-001.md) — Cloud SQL instance missing backup_configuration
- [`STK-GCP-CLOUDSQL-004`](./STK-GCP-CLOUDSQL-004.md) — Cloud SQL instance does not require SSL connections
- [`STK-GCP-CLOUDSQL-005`](./STK-GCP-CLOUDSQL-005.md) — Cloud SQL instance uses end-of-life database version

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-CLOUDSQL-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-CLOUDSQL-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-CLOUDSQL-003
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
