---
title: "SEC-AWS-MSK-001 — MSK cluster allows unencrypted client-broker traffic"
description: "tf-analyze rule SEC-AWS-MSK-001 (HIGH · security): MSK cluster allows unencrypted client-broker traffic"
keywords: "security, high, terraform, iac, aws, cis-{'id': '3.9', 'title': 'Ensure MSK clusters use TLS for client-broker encryption'}"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-MSK-001 \u2014 MSK cluster allows unencrypted client-broker traffic",
  "description": "Require TLS for all client-broker connections:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-MSK-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-MSK-001/"
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
  "keywords": "security, high, terraform, CIS {'id': '3.9', 'title': 'Ensure MSK clusters use TLS for client-broker encryption'}",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-MSK-001 — MSK cluster allows unencrypted client-broker traffic

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-MSK-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **MSK cluster allows unencrypted client-broker traffic.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_msk_cluster` (`client_broker`) matching `/^(PLAINTEXT|TLS_PLAINTEXT)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_msk_cluster` has `client_broker` set to `PLAINTEXT` or `TLS_PLAINTEXT`.
Kafka clients connecting over unencrypted channels expose messages, credentials,
and schema data to network eavesdroppers. Set `client_broker = "TLS"` to require
TLS for all client-to-broker communication.
2. **`resource_missing_arg`** on `aws_msk_cluster` (`client_broker`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_msk_cluster` has no `encryption_in_transit` block. The default
`client_broker` value is `TLS_PLAINTEXT`, which allows plaintext connections.
Explicitly set `client_broker = "TLS"` to enforce encryption.

## Why it likely fired

`aws_msk_cluster` has `client_broker` set to `PLAINTEXT` or `TLS_PLAINTEXT`.
Kafka clients connecting over unencrypted channels expose messages, credentials,
and schema data to network eavesdroppers. Set `client_broker = "TLS"` to require
TLS for all client-to-broker communication.

`aws_msk_cluster` has no `encryption_in_transit` block. The default
`client_broker` value is `TLS_PLAINTEXT`, which allows plaintext connections.
Explicitly set `client_broker = "TLS"` to enforce encryption.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-MSK-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Require TLS for all client-broker connections:

    resource "aws_msk_cluster" "main" {
      # ...
      encryption_info {
        encryption_in_transit {
          client_broker = "TLS"
          in_cluster    = true
        }
        encryption_at_rest {
          encryption_at_rest_kms_key_arn = aws_kms_key.msk.arn
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_msk_cluster" "example" {
  cluster_name = "example"
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }
}
```

## Verification

```sh
`aws kafka describe-cluster --cluster-arn <arn> \
  --query 'ClusterInfo.EncryptionInfo.EncryptionInTransit.ClientBroker'`
must return `"TLS"`.
```

## References

**CIS Benchmark**
  - `CIS 3.9` — Ensure MSK clusters use TLS for client-broker encryption

**PCI-DSS**
  - `Req-4.1`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**Source**
  - [`catalog/SEC-AWS-MSK-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-MSK-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-MSK-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-MSK-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-MSK-001
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
