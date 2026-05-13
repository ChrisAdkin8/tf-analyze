# Expected findings:
#  - SEC-GCP-FIREWALL-LOG-001 MEDIUM — no log_config

resource "google_compute_firewall" "no_log" {
  name    = "allow-internal"
  network = "main"
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
  source_ranges = ["10.0.0.0/8"]
}
