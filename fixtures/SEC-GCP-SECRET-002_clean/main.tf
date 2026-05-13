# Auto-generated clean fixture for SEC-GCP-SECRET-002.
# GCP Secret Manager secret without CMEK on user-managed replication
# This is a CORRECT configuration; SEC-GCP-SECRET-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_secret_manager_secret" "example" {
  secret_id = "example"
  replication {
    user_managed {
      replicas {
        location = "us-central1"
        customer_managed_encryption {
          kms_key_name = "projects/example/locations/us-central1/keyRings/r/cryptoKeys/k"
        }
      }
    }
  }
}
