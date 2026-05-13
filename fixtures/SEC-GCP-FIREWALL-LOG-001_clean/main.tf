# Auto-generated clean fixture for SEC-GCP-FIREWALL-LOG-001.
# GCP firewall rule missing log_config (denied traffic invisible)
# This is a CORRECT configuration; SEC-GCP-FIREWALL-LOG-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_firewall" "example" {
  name    = "allow-ssh"
  network = google_compute_network.main.name
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["10.0.0.0/8"]
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}
