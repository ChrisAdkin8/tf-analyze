# ⚠️ SEC-AWS-ES-003 — OpenSearch domain missing fine-grained access control

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

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

**Source**
  - [`catalog/SEC-AWS-ES-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-ES-003.yaml) — canonical YAML

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

[← Index of all rules](./)
