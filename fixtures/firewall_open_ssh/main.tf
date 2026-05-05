# Expected findings:
#  - SEC-NETWORK-001 CRITICAL — SSH (tcp:22) exposed to 0.0.0.0/0

resource "google_compute_firewall" "ssh_open" {
  name      = "ssh-open"
  network   = "default"
  direction = "INGRESS"

  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
