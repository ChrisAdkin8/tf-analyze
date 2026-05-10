---
title: "ROB-DRIFT-002 — ignore_changes hides too much (wildcard, or tags-wide on a tagged resource)"
description: "tf-analyze rule ROB-DRIFT-002 (MEDIUM · robustness): ignore_changes hides too much (wildcard, or tags-wide on a tagged resource)"
keywords: "robustness, medium, terraform, iac, mitre-T1562.001, cwe-693"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-DRIFT-002 \u2014 ignore_changes hides too much (wildcard, or tags-wide on a tagged resource)",
  "description": "Replace with an explicit list of attributes that must be ignored:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-DRIFT-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-DRIFT-002/"
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
  "keywords": "robustness, medium, terraform, MITRE T1562.001, CWE-693",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# 💡 ROB-DRIFT-002 — ignore_changes hides too much (wildcard, or tags-wide on a tagged resource)

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-DRIFT-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-DRIFT-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-DRIFT-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **ignore_changes hides too much (wildcard, or tags-wide on a tagged resource).** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`grep`** matching `/(?m)^\s*ignore_changes\s*=\s*\[\s*"\*"\s*\]/` — _a textual regex matched somewhere in the file._
  ignore_changes = ["*"] is the array form of the `all` wildcard.
Functionally equivalent to ignore_changes = all but pattern-matches
differently from ROB-DRIFT-001's `= all` form.
2. **`grep`** matching `/(?m)^\s*ignore_changes\s*=\s*\[\s*tags\s*\]/` — _a textual regex matched somewhere in the file._
  ignore_changes = [tags] silently drops every tag drift. On AWS this
includes cost-allocation tags, compliance scope tags, and whatever
`default_tags` propagates from the provider — masking exactly the
attributes auditors expect to be tracked.

## Why it likely fired

ignore_changes = ["*"] is the array form of the `all` wildcard.
Functionally equivalent to ignore_changes = all but pattern-matches
differently from ROB-DRIFT-001's `= all` form.

ignore_changes = [tags] silently drops every tag drift. On AWS this
includes cost-allocation tags, compliance scope tags, and whatever
`default_tags` propagates from the provider — masking exactly the
attributes auditors expect to be tracked.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-DRIFT-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace with an explicit list of attributes that must be ignored:

```hcl
lifecycle {
  ignore_changes = [
    tags["LastModifiedBy"],   # touched by an automation pipeline
    tags["LastBackup"],       # touched by AWS Backup
  ]
}
```

If you really need to ignore the whole `tags` map, document the reason
in a comment on the line above the `ignore_changes` block, and revisit
the decision quarterly. The single-key form (`tags["…"]`) is almost
always what you want — it ignores only the noisy keys, not the audit
trail.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_s3_bucket" "example" {
  bucket = "example"
  lifecycle {
    ignore_changes = [
      tags["LastModifiedBy"],
    ]
  }
}
```

## Verification

After narrowing the list, run `terraform plan` and confirm the legitimate
drift you want to track now appears, while the automation-pipeline writes
no longer trigger churn.

## References

**OWASP IaC Cheat Sheet**
  - [`Runtime / Immutable Infrastructure Model`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1562.001`](https://attack.mitre.org/techniques/T1562/001/)

**CWE**
  - [`CWE-693`](https://cwe.mitre.org/data/definitions/693.html)

**Related rules**
  - [`ROB-DRIFT-001`](./ROB-DRIFT-001.md)

**Source**
  - [`catalog/ROB-DRIFT-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-DRIFT-002.yaml) — canonical YAML

## Family

See also rules in the `ROB-DRIFT-*` family:

- [`ROB-DRIFT-001`](./ROB-DRIFT-001.md) — Resource uses ignore_changes = all
- [`ROB-DRIFT-003`](./ROB-DRIFT-003.md) — ignore_changes lists too many attributes (drift-disable by attrition)

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-DRIFT-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-DRIFT-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-DRIFT-002
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
