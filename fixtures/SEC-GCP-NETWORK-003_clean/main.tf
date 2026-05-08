# Auto-generated clean fixture for SEC-GCP-NETWORK-003.
# VPC subnet missing flow logs
# This is a CORRECT configuration; SEC-GCP-NETWORK-003 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_subnetwork" "example" {
  name          = "example"
  ip_cidr_range = "10.0.0.0/24"
  region        = "us-central1"
  network       = google_compute_network.vpc.id
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}
