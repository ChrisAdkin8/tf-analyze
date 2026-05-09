# ⚠️ SEC-AWS-ES-002 — OpenSearch / Elasticsearch domain missing node-to-node encryption

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

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
