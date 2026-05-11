---
title: "SEC-AWS-ES-003 — OpenSearch domain missing fine-grained access control"
description: "tf-analyze rule SEC-AWS-ES-003 (HIGH · security): OpenSearch domain missing fine-grained access control"
keywords: "security, high, terraform, iac, aws, nist-csf-pr.ds-1, nist-800-53-sc-13, nist-800-53-sc-28, csa-ccm-cek-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-ES-003 \u2014 OpenSearch domain missing fine-grained access control",
  "description": "Enable fine-grained access control with IAM authentication:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-ES-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-ES-003/"
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
  "keywords": "security, high, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-ES-003 — OpenSearch domain missing fine-grained access control

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-ES-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-ES-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-ES-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **OpenSearch domain missing fine-grained access control.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_opensearch_domain` (`advanced_security_options`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_opensearch_domain` has no `advanced_security_options { enabled = true }`.
Without fine-grained access control (FGAC), every request that passes the
network-level controls has full read/write access to all indices. FGAC maps
IAM principals or HTTP basic auth credentials to document-level or index-level
permissions, implementing least-privilege access inside the cluster.

## Why it likely fired

`aws_opensearch_domain` has no `advanced_security_options { enabled = true }`.
Without fine-grained access control (FGAC), every request that passes the
network-level controls has full read/write access to all indices. FGAC maps
IAM principals or HTTP basic auth credentials to document-level or index-level
permissions, implementing least-privilege access inside the cluster.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-ES-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable fine-grained access control with IAM authentication:

    resource "aws_opensearch_domain" "main" {
      # ...
      advanced_security_options {
        enabled                        = true
        anonymous_auth_enabled         = false
        internal_user_database_enabled = false
        master_user_options {
          master_user_arn = aws_iam_role.opensearch_admin.arn
        }
      }
      access_policies = data.aws_iam_policy_document.opensearch.json
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "aws_opensearch_domain" "example" {
  domain_name    = "example"
  engine_version = "OpenSearch_2.11"
  advanced_security_options {
    enabled                        = true
    anonymous_auth_enabled         = false
    internal_user_database_enabled = false
    master_user_options {
      master_user_arn = aws_iam_role.opensearch_admin.arn
    }
  }
}
```

## Verification

```sh
`aws opensearch describe-domain --domain-name <name> \
  --query 'DomainStatus.AdvancedSecurityOptions.Enabled'`
must return `true`.
```

## References

**PCI-DSS**
  - `Req-7.1`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**NIST CSF 2.0**
  - [`PR.DS-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-13`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-13)
  - [`SC-28`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-28)

**CSA CCM v4**
  - [`CEK-03`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AWS-ES-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-ES-003.yaml) — canonical YAML

## Family

See also rules in the `SEC-AWS-ES-*` family:

- [`SEC-AWS-ES-001`](./SEC-AWS-ES-001.md) — OpenSearch / Elasticsearch domain missing encryption at rest
- [`SEC-AWS-ES-002`](./SEC-AWS-ES-002.md) — OpenSearch / Elasticsearch domain missing node-to-node encryption

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-ES-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-ES-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-ES-003
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
