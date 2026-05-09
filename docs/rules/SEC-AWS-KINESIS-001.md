# 💡 SEC-AWS-KINESIS-001 — Kinesis Data Stream not encrypted with KMS

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Kinesis Data Stream not encrypted with KMS.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_kinesis_stream` (`encryption_type`) — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_kinesis_stream` has `encryption_type` absent or not set to `KMS`.
The default `NONE` encryption leaves stream data in plaintext at rest.
Anyone with access to the underlying storage can read records. Use
KMS encryption so that key-policy controls who can decrypt stream data.

## Why it likely fired

`aws_kinesis_stream` has `encryption_type` absent or not set to `KMS`.
The default `NONE` encryption leaves stream data in plaintext at rest.
Anyone with access to the underlying storage can read records. Use
KMS encryption so that key-policy controls who can decrypt stream data.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-KINESIS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable KMS encryption on every Kinesis stream:

    resource "aws_kinesis_stream" "main" {
      name             = "main"
      shard_count      = 1
      encryption_type  = "KMS"
      kms_key_id       = aws_kms_key.kinesis.id
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_kinesis_stream" "example" {
  name            = "example"
  shard_count     = 1
  encryption_type = "KMS"
  kms_key_id      = aws_kms_key.kinesis.id
}
```

## Verification

```sh
`aws kinesis describe-stream-summary --stream-name <name> \
  --query 'StreamDescriptionSummary.EncryptionType'`
must return `"KMS"`.
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**Source**
  - [`catalog/SEC-AWS-KINESIS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-KINESIS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-KINESIS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-KINESIS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-KINESIS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
