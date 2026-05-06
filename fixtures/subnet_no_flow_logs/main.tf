# Expected findings:
#  - SEC-GCP-NETWORK-003 HIGH — VPC subnet missing log_config.aggregation_interval

resource "google_compute_subnetwork" "no_flow_logs" {
  name          = "no-flow-logs"
  ip_cidr_range = "10.0.0.0/24"
  region        = "us-central1"
  network       = "default"

  # No log_config block — VPC flow logs disabled.
}
