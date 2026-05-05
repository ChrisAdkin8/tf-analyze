# OWASP A04:2021 — Insecure Design
# Cloud: GCP
#
# "Insecure design" is the absence of defence-in-depth — a system
# may follow every individual best practice and still be brittle if
# its overall architecture relies on a single control. The classic
# GCP example is a workload that uses one shared service account for
# every component, so a compromise of any pod inherits access to all
# storage, all secrets, all databases. Two anti-patterns:
#
#   1. Single-tenant identity: one SA spans frontend + backend +
#      batch + cron. Lateral movement inside the project is free.
#   2. No prevent_destroy on stateful resources. A typo'd
#      `terraform destroy` against the wrong tfvars takes down the
#      entire data plane.
#
# Real-world impact:
#   - A compromised frontend pod reads the same secrets as the
#     payments backend.
#   - A 3am rollback removes the production database; backups are
#     still in storage but every consumer is now broken.
#
# Expected tf-analyze findings:
#   - ROB-LIFECYCLE-001  HIGH    Stateful resource missing prevent_destroy
#   - ROB-LIFECYCLE-002  HIGH    Stateful resource missing prevent_destroy
#
# Fix summary: one SA per workload boundary, narrow IAM per SA,
# `lifecycle { prevent_destroy = true }` on every database / state
# bucket / KMS root — these aren't separate controls, they're a
# single layered design pattern.

# One SA used by everything: frontend, backend, cron, batch.
resource "google_service_account" "monolith" {
  account_id   = "monolith"
  display_name = "Used by every workload — single point of failure"
}

# Stateful Spanner instance with no prevent_destroy. A typo'd destroy
# wipes the production data plane.
resource "google_spanner_instance" "main" {
  name             = "main"
  config           = "regional-us-central1"
  display_name     = "main"
  processing_units = 100
}

# State bucket also unprotected.
resource "google_storage_bucket" "tfstate" {
  name                        = "demo-tfstate"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }
  # No lifecycle { prevent_destroy = true } — destroying the state
  # bucket disables every other Terraform-managed resource.
}
