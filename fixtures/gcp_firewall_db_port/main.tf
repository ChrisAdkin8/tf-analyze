# Expected findings: SEC-GCP-NETWORK-004

resource "google_compute_network" "main" {
  name = "demo-network"
}

# Firewall rule exposing PostgreSQL to the entire internet.
resource "google_compute_firewall" "open_postgres" {
  name    = "allow-postgres-all"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }

  source_ranges = ["0.0.0.0/0"]
}
