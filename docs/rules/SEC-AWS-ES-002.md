---
title: "SEC-AWS-ES-002 — OpenSearch / Elasticsearch domain missing node-to-node encryption"
description: "tf-analyze rule SEC-AWS-ES-002 (HIGH · security): OpenSearch / Elasticsearch domain missing node-to-node encryption"
keywords: "security, high, terraform, iac, aws, cis-{'id': '2.8', 'title': 'Ensure that OpenSearch domains have node-to-node encryption enabled'}"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-ES-002 \u2014 OpenSearch / Elasticsearch domain missing node-to-node encryption",
  "description": "Enable node-to-node encryption:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-ES-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-ES-002/"
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
  "keywords": "security, high, terraform, CIS {'id': '2.8', 'title': 'Ensure that OpenSearch domains have node-to-node encryption enabled'}",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-ES-002 — OpenSearch / Elasticsearch domain missing node-to-node encryption

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-ES-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **OpenSearch / Elasticsearch domain missing node-to-node encryption.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_opensearch_domain` (`node_to_node_encryption`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_opensearch_domain` has no `node_to_node_encryption { enabled = true }`.
Without this setting, data transferred between cluster nodes travels
unencrypted inside the VPC. An adversary with VPC-level access (e.g.,
via a compromised EC2 instance) can intercept index data in transit.
2. **`resource_missing_arg`** on `aws_elasticsearch_domain` (`node_to_node_encryption`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_elasticsearch_domain` (legacy) missing node-to-node encryption.

## Why it likely fired

`aws_opensearch_domain` has no `node_to_node_encryption { enabled = true }`.
Without this setting, data transferred between cluster nodes travels
unencrypted inside the VPC. An adversary with VPC-level access (e.g.,
via a compromised EC2 instance) can intercept index data in transit.

`aws_elasticsearch_domain` (legacy) missing node-to-node encryption.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-ES-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable node-to-node encryption:

    resource "aws_opensearch_domain" "main" {
      # ...
      node_to_node_encryption {
        enabled = true
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "aws_opensearch_domain" "example" {
  domain_name    = "example"
  engine_version = "OpenSearch_2.11"
  node_to_node_encryption {
    enabled = true
  }
}
```

## Verification

```sh
`aws opensearch describe-domain --domain-name <name> \
  --query 'DomainStatus.NodeToNodeEncryptionOptions'`
must show `Enabled: true`.
```

## References

**CIS Benchmark**
  - `CIS 2.8` — Ensure that OpenSearch domains have node-to-node encryption enabled

**PCI-DSS**
  - `Req-4.1`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**Source**
  - [`catalog/SEC-AWS-ES-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-ES-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-ES-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-ES-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-ES-002
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
