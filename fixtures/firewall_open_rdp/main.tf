# Expected findings:
#  - SEC-GCP-NETWORK-002 CRITICAL — RDP (tcp:3389) exposed to 0.0.0.0/0

resource "google_compute_firewall" "rdp_open" {
  name      = "rdp-open"
  network   = "default"
  direction = "INGRESS"

  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}
