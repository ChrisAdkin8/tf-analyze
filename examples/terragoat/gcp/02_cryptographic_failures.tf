# OWASP A02:2021 — Cryptographic Failures
# Cloud: GCP
#
# Three cryptographic failure modes commonly seen in GCP Terraform:
#
#   1. CMEK key with no rotation period — a stolen key material
#      remains valid forever. CIS GCP 1.10 requires ≤90 days.
#   2. Bucket encrypted with a key whose key ring lives in a
#      different region. The encrypt/decrypt path crosses regions,
#      breaks regional durability guarantees, and silently doubles
#      egress cost. Also a classic data-residency violation.
#   3. Sensitive output not marked `sensitive = true` — the value
#      ends up in `terraform plan` output, CI logs, and any operator's
#      shell history.
#
# Real-world impact:
#   - Long-lived KEKs amplify the blast radius of any IAM compromise
#     on the KMS resource.
#   - Cross-region CMEK is a compliance violation (GDPR, FedRAMP) and
#     a recovery hazard during regional outages.
#   - Plaintext outputs in CI logs are the #1 source of cred leaks
#     in well-instrumented pipelines.
#
# Expected tf-analyze findings:
#   - STK-GCP-KMS-001           HIGH    KMS crypto key missing rotation period
#   - STK-GCP-KMS-LOCATION-001  HIGH    CMEK consumer location mismatches key ring
#   - SEC-SENSITIVE-001         HIGH    Sensitive output not marked sensitive=true
#   - STK-GCP-PUBSUB-001        MEDIUM  Pub/Sub topic without customer-managed encryption key
#
# Fix summary: add `rotation_period = "7776000s"` (90 days) on every
# symmetric crypto key, co-locate consumers with their key rings, and
# mark every output that touches a sensitive variable.

resource "google_kms_key_ring" "primary" {
  name     = "primary"
  location = "us-east1"
}

resource "google_kms_crypto_key" "data" {
  name     = "data"
  key_ring = google_kms_key_ring.primary.id
  purpose  = "ENCRYPT_DECRYPT"
  # rotation_period intentionally omitted — keys live forever.

  lifecycle {
    prevent_destroy = true
  }
}

# Consumer in us-central1, key ring in us-east1 — region mismatch.
resource "google_storage_bucket" "encrypted_cross_region" {
  name                        = "demo-encrypted-cross-region"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.data.id
  }

  versioning {
    enabled = true
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Pub/Sub topic without CMEK — messages encrypted with Google-managed
# keys only. For topics carrying PII or regulated data, a CMEK binding
# is required so the organisation controls key rotation and access
# revocation.
resource "google_pubsub_topic" "no_cmek" {
  name = "demo-events"
  # kms_key_name intentionally absent
}

variable "vault_token" {
  description = "Vault root token; consumed by downstream modules."
  type        = string
  sensitive   = true
}

# Output forwards a sensitive variable but is itself unmarked. Plan
# output and CI logs will print the value in cleartext.
output "vault_token_echo" {
  value = var.vault_token
  # sensitive = true intentionally omitted
}
