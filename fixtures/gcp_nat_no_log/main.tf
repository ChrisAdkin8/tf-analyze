# Expected findings:
#  - STK-GCP-NAT-001 MEDIUM — no log_config

resource "google_compute_router_nat" "no_log" {
  name                               = "main-nat"
  router                             = "main-router"
  region                             = "us-central1"
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}
