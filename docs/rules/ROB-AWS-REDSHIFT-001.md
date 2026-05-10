---
title: "ROB-AWS-REDSHIFT-001 — Redshift cluster has no automated snapshot retention"
description: "tf-analyze rule ROB-AWS-REDSHIFT-001 (MEDIUM · robustness): Redshift cluster has no automated snapshot retention"
keywords: "robustness, medium, terraform, iac, aws, mitre-T1490"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-AWS-REDSHIFT-001 \u2014 Redshift cluster has no automated snapshot retention",
  "description": "Set a non-zero retention period:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-REDSHIFT-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-REDSHIFT-001/"
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
  "keywords": "robustness, medium, terraform, MITRE T1490",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# 💡 ROB-AWS-REDSHIFT-001 — Redshift cluster has no automated snapshot retention

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-AWS-REDSHIFT-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-AWS-REDSHIFT-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-AWS-REDSHIFT-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Redshift cluster has no automated snapshot retention.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_redshift_cluster` (`automated_snapshot_retention_period`) matching `/^0$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_redshift_cluster` has `automated_snapshot_retention_period = 0`.
Setting retention to 0 disables automated snapshots entirely. Without
snapshots, accidental data deletion or cluster corruption cannot be
recovered without a full reload from source systems.

## Why it likely fired

`aws_redshift_cluster` has `automated_snapshot_retention_period = 0`.
Setting retention to 0 disables automated snapshots entirely. Without
snapshots, accidental data deletion or cluster corruption cannot be
recovered without a full reload from source systems.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-REDSHIFT-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set a non-zero retention period:

    resource "aws_redshift_cluster" "main" {
      # ...
      automated_snapshot_retention_period = 7
    }

Maximum is 35 days. For longer-term retention, copy snapshots to S3 via
`aws_redshift_snapshot_copy_grant`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_redshift_cluster" "example" {
  cluster_identifier                  = "example"
  automated_snapshot_retention_period = 7
}
```

## Verification

```sh
`aws redshift describe-clusters --cluster-identifier <id> \
  --query 'Clusters[*].AutomatedSnapshotRetentionPeriod'`
must return a value greater than 0.
```

## References

**SOC 2 Trust Services Criteria**
  - `A1.2`

**MITRE ATT&CK**
  - [`T1490`](https://attack.mitre.org/techniques/T1490/)

**Source**
  - [`catalog/ROB-AWS-REDSHIFT-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-REDSHIFT-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-REDSHIFT-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-REDSHIFT-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-REDSHIFT-001
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
