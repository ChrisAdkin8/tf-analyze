# ⚠️ SEC-AWS-DOCDB-001 — DocumentDB cluster storage not encrypted

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **DocumentDB cluster storage not encrypted.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_docdb_cluster` (`storage_encrypted`) — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_docdb_cluster` has `storage_encrypted = false` or the attribute
is absent. DocumentDB defaults to unencrypted storage. Sensitive
application data stored in DocumentDB collections is exposed to anyone
with access to the underlying EBS volumes.

## Why it likely fired

`aws_docdb_cluster` has `storage_encrypted = false` or the attribute
is absent. DocumentDB defaults to unencrypted storage. Sensitive
application data stored in DocumentDB collections is exposed to anyone
with access to the underlying EBS volumes.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-DOCDB-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable storage encryption:

    resource "aws_docdb_cluster" "main" {
      cluster_identifier      = "main"
      storage_encrypted       = true
      kms_key_id              = aws_kms_key.docdb.arn
    }

Encryption can only be configured at cluster creation.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "aws_docdb_cluster" "example" {
  cluster_identifier = "example"
  storage_encrypted  = true
  kms_key_id         = aws_kms_key.docdb.arn
}
```

## Verification

```sh
`aws docdb describe-db-clusters --db-cluster-identifier <id> \
  --query 'DBClusters[*].StorageEncrypted'`
must return `true`.
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**Source**
  - [`catalog/SEC-AWS-DOCDB-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-DOCDB-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-DOCDB-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-DOCDB-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-DOCDB-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
