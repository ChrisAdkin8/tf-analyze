# ⚠️ SEC-AWS-REDSHIFT-001 — Redshift cluster encryption disabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Redshift cluster encryption disabled.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_redshift_cluster` (`encrypted`) — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_redshift_cluster` has `encrypted = false` or the attribute is absent.
Unencrypted Redshift clusters expose warehouse data — which typically contains
production analytics, PII, and financial records — to anyone with access to
the underlying storage. Encryption is required by PCI-DSS Req-3.4 and CIS 2.3.

## Why it likely fired

`aws_redshift_cluster` has `encrypted = false` or the attribute is absent.
Unencrypted Redshift clusters expose warehouse data — which typically contains
production analytics, PII, and financial records — to anyone with access to
the underlying storage. Encryption is required by PCI-DSS Req-3.4 and CIS 2.3.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-REDSHIFT-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable encryption with a CMK:

    resource "aws_redshift_cluster" "main" {
      cluster_identifier = "main"
      # ...
      encrypted  = true
      kms_key_id = aws_kms_key.redshift.arn
    }

Encryption cannot be added to an existing cluster without a snapshot-restore
cycle. Plan for this during initial provisioning.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "aws_redshift_cluster" "example" {
  cluster_identifier = "example"
  encrypted          = true
  kms_key_id         = aws_kms_key.redshift.arn
}
```

## Verification

```sh
`aws redshift describe-clusters --cluster-identifier <id> \
  --query 'Clusters[*].Encrypted'`
must return `true`.
```

## References

**CIS Benchmark**
  - `CIS 2.3` — Ensure that encryption is enabled for Amazon Redshift Clusters

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**Source**
  - [`catalog/SEC-AWS-REDSHIFT-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-REDSHIFT-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-REDSHIFT-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-REDSHIFT-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-REDSHIFT-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
