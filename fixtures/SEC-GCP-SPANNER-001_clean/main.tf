# Auto-generated clean fixture for SEC-GCP-SPANNER-001.
# GCP Spanner instance not encrypted with customer-managed key
# This is a CORRECT configuration; SEC-GCP-SPANNER-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_spanner_database" "example" {
  instance = google_spanner_instance.example.name
  name     = "example"
  encryption_config {
    kms_key_name = "projects/example/locations/us-central1/keyRings/r/cryptoKeys/k"
  }
}
