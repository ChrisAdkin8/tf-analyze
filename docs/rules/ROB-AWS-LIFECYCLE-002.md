---
title: "ROB-AWS-LIFECYCLE-002 — S3 bucket has force_destroy enabled"
description: "tf-analyze rule ROB-AWS-LIFECYCLE-002 (HIGH · robustness): S3 bucket has force_destroy enabled"
keywords: "robustness, high, terraform, iac, aws, mitre-T1485, nist-csf-pr.ip-4, nist-800-53-cm-3, csa-ccm-bcr-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-AWS-LIFECYCLE-002 \u2014 S3 bucket has force_destroy enabled",
  "description": "Remove `force_destroy = true` from production buckets:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-LIFECYCLE-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AWS-LIFECYCLE-002/"
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
  "keywords": "robustness, high, terraform, MITRE T1485",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# ⚠️ ROB-AWS-LIFECYCLE-002 — S3 bucket has force_destroy enabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-AWS-LIFECYCLE-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-AWS-LIFECYCLE-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-AWS-LIFECYCLE-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **S3 bucket has force_destroy enabled.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_s3_bucket` (`force_destroy`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_s3_bucket` with `force_destroy = true`. Terraform will silently
delete every object in the bucket — including objects written by
applications after the infrastructure was provisioned — on the next
`terraform destroy`. This makes data loss a single command away.

## Why it likely fired

`aws_s3_bucket` with `force_destroy = true`. Terraform will silently
delete every object in the bucket — including objects written by
applications after the infrastructure was provisioned — on the next
`terraform destroy`. This makes data loss a single command away.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-LIFECYCLE-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove `force_destroy = true` from production buckets:

    resource "aws_s3_bucket" "app" {
      bucket = "app-data"
      # force_destroy = true  # remove this line
    }

For development/test environments where force_destroy is intentional,
add an inline comment explaining why and suppress the finding:
    # tf-analyze:ignore ROB-AWS-LIFECYCLE-002
    force_destroy = true  # test env only — data is ephemeral

Pair production buckets with `lifecycle { prevent_destroy = true }` for
a double guard.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_s3_bucket" "example" {
  # ... other arguments ...
  force_destroy = false
}
```

## Verification

```sh
`aws s3api get-bucket-policy --bucket <name>` (policy cannot re-enable
forced deletion). Confirm `force_destroy` is absent or `false` in
`terraform show`.
```

## References

**OWASP IaC Cheat Sheet**
  - [`Deploy / Resource Decommissioning Process`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1485`](https://attack.mitre.org/techniques/T1485/)

**NIST CSF 2.0**
  - [`PR.IP-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CM-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cm-3)

**CSA CCM v4**
  - [`BCR-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/ROB-AWS-LIFECYCLE-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-LIFECYCLE-002.yaml) — canonical YAML

## Family

See also rules in the `ROB-AWS-LIFECYCLE-*` family:

- [`ROB-AWS-LIFECYCLE-001`](./ROB-AWS-LIFECYCLE-001.md) — Stateful AWS resource missing lifecycle.prevent_destroy

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-LIFECYCLE-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-LIFECYCLE-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-LIFECYCLE-002
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
