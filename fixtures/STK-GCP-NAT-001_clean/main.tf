# Auto-generated clean fixture for STK-GCP-NAT-001.
# GCP Cloud NAT missing logging
# This is a CORRECT configuration; STK-GCP-NAT-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_router_nat" "example" {
  name                               = "example"
  router                             = google_compute_router.example.name
  region                             = "us-central1"
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  log_config {
    enable = true
    filter = "ALL"
  }
}
