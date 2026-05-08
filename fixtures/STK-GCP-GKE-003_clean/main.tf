# Auto-generated clean fixture for STK-GCP-GKE-003.
# GKE cluster missing application-layer secrets encryption
# This is a CORRECT configuration; STK-GCP-GKE-003 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_container_cluster" "example" {
  name     = "example"
  location = "us-central1"
  database_encryption {
    state    = "ENCRYPTED"
    key_name = google_kms_crypto_key.gke.id
  }
}
