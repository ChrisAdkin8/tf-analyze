# OWASP A09:2021 — Security Logging and Monitoring Failures
# Cloud: GCP
#
# Two integrity-of-evidence failures:
#
#   1. Cloud Audit Logs not configured at the project level. ADMIN_READ,
#      DATA_READ, and DATA_WRITE for `allServices` (or per-API) is the
#      baseline that lets you reconstruct who did what, when. Without
#      it, an incident has no forensic timeline.
#   2. Audit-log bucket itself unprotected against public access. The
#      bucket that receives access logs for a sensitive bucket needs
#      tighter controls than the source — exfiltrating the access log
#      tells an attacker which objects exist and how often they're
#      read, even without read access to the source. (This is the
#      classic CKV2 graph-style finding — the source bucket may be
#      perfectly fine, but its log target is the leak.)
#
# Real-world impact:
#   - No audit logs = post-incident investigation pulls "we don't
#     know" from a closed Slack thread.
#   - Public log bucket = an attacker can probe object presence and
#     access frequency without authenticating against the source
#     bucket.
#
# Expected tf-analyze findings:
#   - SEC-GCP-LOGGING-001         HIGH   Cloud Audit Logs not configured
#   - STK-GCP-GCS-LOGGING-001     HIGH   GCS bucket logging target lacks public_access_prevention
#   - SEC-GCP-NETWORK-003         HIGH   VPC subnet missing flow logs
#   - STK-GCP-DNS-001             HIGH   Cloud DNS managed zone missing DNSSEC
#
# Fix summary: declare `google_project_iam_audit_config` for
# allServices in the root module; lock down every bucket that
# receives `logging.log_bucket` traffic with the same hardening
# as the source.

# Source bucket is perfectly fine on its own.
resource "google_storage_bucket" "logged_source" {
  name                        = "demo-logged-source"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.audit_target.name
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Logging target bucket missing public_access_prevention — the leak.
resource "google_storage_bucket" "audit_target" {
  name                        = "demo-audit-target"
  location                    = "US"
  uniform_bucket_level_access = true
  # public_access_prevention intentionally omitted — receives logs
  # from `logged_source` above; STK-GCP-GCS-LOGGING-001 fires here.

  versioning {
    enabled = true
  }
}

# google_project_iam_audit_config intentionally omitted at the project
# level — SEC-GCP-LOGGING-001 fires.

# Subnet without flow logs — SEC-GCP-NETWORK-003.
resource "google_compute_subnetwork" "no_flow_logs" {
  name          = "demo-no-flow-logs"
  ip_cidr_range = "10.10.0.0/24"
  region        = "us-central1"
  network       = "default"

  # log_config intentionally omitted — SEC-GCP-NETWORK-003 fires.
}

# DNS managed zone without DNSSEC — STK-GCP-DNS-001.
resource "google_dns_managed_zone" "no_dnssec" {
  name     = "demo-no-dnssec"
  dns_name = "demo.example.com."

  # dnssec_config intentionally omitted — STK-GCP-DNS-001 fires.
}
