# 💡 SEC-GCP-COMPUTE-DISK-001 — GCP compute disk not encrypted with CSEK/CMEK

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **GCP compute disk not encrypted with CSEK/CMEK.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_compute_disk` (`disk_encryption_key`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_compute_disk` has no `disk_encryption_key` block. Without a
customer-managed encryption key (CMEK) or customer-supplied encryption
key (CSEK), the disk is encrypted with a Google-managed key. This
prevents independent key rotation, key revocation for incident response,
and satisfying compliance requirements that mandate customer-controlled
encryption.
2. **`resource_missing_arg`** on `google_compute_instance` (`disk_encryption_key`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_compute_instance` boot disk has no `disk_encryption_key_raw`.
The boot disk defaults to Google-managed encryption.

## Why it likely fired

`google_compute_disk` has no `disk_encryption_key` block. Without a
customer-managed encryption key (CMEK) or customer-supplied encryption
key (CSEK), the disk is encrypted with a Google-managed key. This
prevents independent key rotation, key revocation for incident response,
and satisfying compliance requirements that mandate customer-controlled
encryption.

`google_compute_instance` boot disk has no `disk_encryption_key_raw`.
The boot disk defaults to Google-managed encryption.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-COMPUTE-DISK-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Specify a KMS key for disk encryption:

    resource "google_compute_disk" "data" {
      name = "data"
      type = "pd-ssd"
      zone = "us-central1-a"

      disk_encryption_key {
        kms_key_self_link = google_kms_crypto_key.disk.id
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_compute_disk" "example" {
  name = "example"
  type = "pd-ssd"
  zone = "us-central1-a"
  disk_encryption_key {
    kms_key_self_link = google_kms_crypto_key.disk.id
  }
}
```

## Verification

```sh
`gcloud compute disks describe <name> --zone <zone> \
  --format='get(diskEncryptionKey.kmsKeyName)'`
must return a KMS key resource path.
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**Source**
  - [`catalog/SEC-GCP-COMPUTE-DISK-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-COMPUTE-DISK-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-COMPUTE-DISK-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-COMPUTE-DISK-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-COMPUTE-DISK-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
