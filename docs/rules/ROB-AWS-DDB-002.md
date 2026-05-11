---
title: "ROB-AWS-DDB-002 — DynamoDB table missing point-in-time recovery"
description: "tf-analyze rule ROB-AWS-DDB-002 (MEDIUM · robustness): DynamoDB table missing point-in-time recovery"
keywords: "robustness, medium, terraform, iac, aws, mitre-T1490, nist-csf-rc.rp-1, nist-800-53-cp-9, csa-ccm-bcr-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-AWS-DDB-002 \u2014 DynamoDB table missing point-in-time recovery",
  "description": "Enable PITR on all production tables:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-DDB-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-DDB-002/"
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

# 💡 ROB-AWS-DDB-002 — DynamoDB table missing point-in-time recovery

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-AWS-DDB-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-AWS-DDB-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-AWS-DDB-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **DynamoDB table missing point-in-time recovery.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`graph_check`** — _a corpus-wide graph check fired (cross-resource invariant)._
  `aws_dynamodb_table` without `point_in_time_recovery { enabled = true }`.
Without PITR, accidental writes, deletes, or application bugs can cause
permanent data loss. PITR provides a 35-day rolling backup window with
second-level restore granularity at no additional IOPS cost.

## Why it likely fired

`aws_dynamodb_table` without `point_in_time_recovery { enabled = true }`.
Without PITR, accidental writes, deletes, or application bugs can cause
permanent data loss. PITR provides a 35-day rolling backup window with
second-level restore granularity at no additional IOPS cost.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-DDB-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable PITR on all production tables:

    resource "aws_dynamodb_table" "app" {
      name = "app"

      point_in_time_recovery {
        enabled = true
      }
    }

PITR restores are performed using `RestoreTableToPointInTime` and create
a new table — they do not overwrite the original.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_dynamodb_table" "example" {
  name = "example"

  point_in_time_recovery {
    enabled = true
  }
}
```

## Verification

```sh
`aws dynamodb describe-continuous-backups --table-name <name> \
  --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus'`
must return `"ENABLED"`.
```

## References

**SOC 2 Trust Services Criteria**
  - `A1.2`

**MITRE ATT&CK**
  - [`T1490`](https://attack.mitre.org/techniques/T1490/)

**NIST CSF 2.0**
  - [`RC.RP-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CP-9`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cp-9)

**CSA CCM v4**
  - [`BCR-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/ROB-AWS-DDB-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-DDB-002.yaml) — canonical YAML

## Family

See also rules in the `ROB-AWS-DDB-*` family:

- [`ROB-AWS-DDB-001`](./ROB-AWS-DDB-001.md) — DynamoDB table missing deletion protection

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-DDB-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-DDB-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-DDB-002
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
