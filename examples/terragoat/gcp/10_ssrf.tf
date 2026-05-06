# OWASP A10:2021 — Server-Side Request Forgery
# Cloud: GCP
#
# In an IaC context, "SSRF" maps to network configurations that let an
# in-cluster workload reach destinations the operator didn't intend —
# either external (egress to attacker-controlled hosts) or internal
# (the metadata service, peer projects, peer VPCs). Three control
# absences are the usual cause:
#
#   1. No VPC Service Controls perimeter around sensitive APIs (BQ,
#      GCS, KMS). An exfiltrating workload writes to its own bucket
#      in a different project, undetected.
#   2. Cloud SQL with `ipv4_enabled = true` — the DB has a public IP
#      reachable from any VPC including the attacker's. Even with
#      `authorized_networks`, a workload that egresses freely can
#      reach it.
#   3. Cloud Run / GKE workloads without restrictive egress policies.
#      An RCE via a deserialisation flaw can fetch
#      `http://metadata.google.internal/...` and steal the SA token.
#
# Real-world impact:
#   - Capital One 2019 — SSRF on a WAF instance fetched the metadata
#     service token, which had broad S3 permissions.
#   - Less famously: workloads making outbound HTTP to attacker-
#     controlled hosts as part of a software supply chain attack on
#     the build image.
#
# Expected tf-analyze findings:
#   - SEC-GCP-SQL-PUBLIC-001    HIGH    Cloud SQL instance permits public IPv4
#   (note: full SSRF coverage requires VPC SC and metadata-service
#   protections that aren't yet first-class catalogue rules — this
#   file primarily fires the existing rule and serves as documentation
#   for the broader category.)
#
# Fix summary: enable VPC Service Controls on every sensitive API,
# bind workloads to dedicated VPCs with restrictive Cloud NAT egress,
# and set `metadata = { disable-legacy-endpoints = "true" }` on every
# VM / node pool.

# Cloud SQL with public IP — workloads inside or outside the VPC can
# reach it.
resource "google_sql_database_instance" "public_db" {
  name             = "demo-public-db"
  region           = "us-central1"
  database_version = "POSTGRES_15"

  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "office"
        value = "203.0.113.0/24"
      }
    }
    backup_configuration {
      enabled = true
    }
  }

  deletion_protection = true
}

# Cloud Run with `ingress = "INGRESS_TRAFFIC_ALL"` — the service is
# reachable from the public internet. tf-analyze does not yet have a
# specific rule for Cloud Run ingress; this is documented as a
# placeholder for a future catalogue addition.
resource "google_cloud_run_v2_service" "publicly_reachable" {
  name     = "demo-cloudrun-public"
  location = "us-central1"
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    containers {
      image = "us-central1-docker.pkg.dev/demo-project/demo-repo/demo:latest"
    }
  }
}
