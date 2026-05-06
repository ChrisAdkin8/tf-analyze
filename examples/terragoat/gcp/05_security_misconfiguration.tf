# OWASP A05:2021 — Security Misconfiguration
# Cloud: GCP
#
# The largest OWASP category by volume — anything that's wrong by
# default but right with one extra line. GCP's most common
# misconfigurations:
#
#   1. Compute instances using the project's default Compute SA
#      (`<project-number>-compute@developer.gserviceaccount.com`)
#      which holds `roles/editor` project-wide.
#   2. VMs with `access_config {}` — even an empty block requests an
#      ephemeral public IP, exposing sshd and any listening port to
#      the internet.
#   3. Firewall rules with `source_ranges = ["0.0.0.0/0"]` and
#      `allow { ports = ["22"] }` — world-open SSH is the most-
#      attacked surface on GCP.
#   4. Cloud SQL with `ipv4_enabled = true` — the database has a
#      public IP. authorized_networks gating helps but is one
#      misconfiguration away from world-readable.
#   5. GCS buckets without `public_access_prevention = "enforced"`
#      and without `uniform_bucket_level_access` — legacy ACLs and
#      anonymous IAM bindings are silently possible.
#
# Real-world impact: any of these on its own is an outage waiting to
# happen. The defaults here are the same defaults that bridgecrew /
# tfsec / Checkov flag tens of millions of times a year against
# real-world repos.
#
# Expected tf-analyze findings:
#   - SEC-GCP-COMPUTE-SA-001          HIGH       Compute instance uses default Compute SA
#   - SEC-GCP-COMPUTE-PUBLIC-IP-001   HIGH       Compute instance has public IP via access_config
#   - SEC-GCP-NETWORK-001             CRITICAL   SSH (tcp:22) exposed to 0.0.0.0/0
#   - SEC-GCP-NETWORK-002             CRITICAL   RDP (tcp:3389) exposed to 0.0.0.0/0
#   - SEC-GCP-SQL-PUBLIC-001          HIGH       Cloud SQL instance permits public IPv4
#   - STK-GCP-CLOUDSQL-003            HIGH       Cloud SQL instance missing deletion_protection
#   - STK-GCP-CLOUDSQL-004            HIGH       Cloud SQL instance does not require SSL
#   - SEC-GCP-BUCKET-001              HIGH       GCS bucket missing public_access_prevention=enforced
#   - SEC-GCP-BUCKET-002              MEDIUM     GCS bucket missing uniform_bucket_level_access
#   - OPS-ENV-001                     HIGH       Prod-scoped resource lacks deletion_protection
#
# Fix summary: each fix is one-to-three lines. The catalogue
# recommendations link the relevant gcloud verification commands.

resource "google_compute_instance" "exposed" {
  name         = "demo-exposed"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
    access_config {
      # Requests an ephemeral public IP — the VM is now on the
      # internet with whatever sshd / firewall rules the OS image
      # ships with.
    }
  }
  # service_account intentionally omitted → default Compute SA
}

resource "google_compute_firewall" "ssh_open" {
  name      = "demo-ssh-open"
  network   = "default"
  direction = "INGRESS"

  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# World-open RDP — SEC-GCP-NETWORK-002.
resource "google_compute_firewall" "rdp_open" {
  name      = "demo-rdp-open"
  network   = "default"
  direction = "INGRESS"

  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}

resource "google_sql_database_instance" "main" {
  name             = "demo-main"
  region           = "us-central1"
  database_version = "POSTGRES_15"

  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      ipv4_enabled = true
    }
    backup_configuration {
      enabled = true
    }
  }

  deletion_protection = true
}

# Cloud SQL without deletion_protection — STK-GCP-CLOUDSQL-003.
resource "google_sql_database_instance" "no_dp" {
  name             = "demo-no-dp"
  region           = "us-central1"
  database_version = "POSTGRES_15"

  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      ipv4_enabled = false
    }
    backup_configuration {
      enabled = true
    }
  }

  # deletion_protection intentionally omitted — STK-GCP-CLOUDSQL-003 fires.
}

# Bucket labeled prod, no enforced public access prevention, no UBLA,
# no deletion_protection equivalent (lifecycle.prevent_destroy on
# google_storage_bucket).
resource "google_storage_bucket" "prod_data" {
  name     = "demo-prod-data"
  location = "US"

  labels = {
    environment = "prod"
  }
}
