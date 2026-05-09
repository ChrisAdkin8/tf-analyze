---
title: "ROB-REMOTESTATE-001 — terraform_remote_state data source couples modules implicitly"
description: "tf-analyze rule ROB-REMOTESTATE-001 (MEDIUM · robustness): terraform_remote_state data source couples modules implicitly"
keywords: "robustness, medium, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-REMOTESTATE-001 \u2014 terraform_remote_state data source couples modules implicitly",
  "description": "Replace `data.terraform_remote_state` with an explicit interface \u2014 either\nmodule outputs passed via `inputs`, or provider data sources that read the\nunderlying resource by attribute (e.g., `data.google_storage_bucket.x`).",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-REMOTESTATE-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-REMOTESTATE-001/"
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
  "keywords": "robustness, medium, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# 💡 ROB-REMOTESTATE-001 — terraform_remote_state data source couples modules implicitly

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-REMOTESTATE-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-REMOTESTATE-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-REMOTESTATE-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **terraform_remote_state data source couples modules implicitly.** This rule has `default_urgency: MEDIUM` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`remote_state_present`** — _a `remote_state_present` pattern._
  data "terraform_remote_state" couples this config to another root's state layout

## Why it likely fired

data "terraform_remote_state" couples this config to another root's state layout

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-REMOTESTATE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `data.terraform_remote_state` with an explicit interface — either
module outputs passed via `inputs`, or provider data sources that read the
underlying resource by attribute (e.g., `data.google_storage_bucket.x`).

terraform_remote_state has two failure modes that bite in production:
 1. A rename of the upstream output (non-breaking at its producer) becomes
    a plan-time failure here, with a message pointing nowhere useful.
 2. Callers need read access to the upstream state bucket, which
    over-scopes IAM (the bucket contains secrets in .tfstate attributes).

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
data "aws_ssm_parameter" "vpc_id" {
  name = "/networking/vpc_id"
}
locals {
  vpc_id = data.aws_ssm_parameter.vpc_id.value
}
```

## Verification

Grep for `data "terraform_remote_state"` under the scanned path — zero hits.
If the replacement uses provider data sources, run `terraform plan` and
confirm the same values resolve.

## References

**Source**
  - [`catalog/ROB-REMOTESTATE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-REMOTESTATE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-REMOTESTATE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-REMOTESTATE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-REMOTESTATE-001
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
