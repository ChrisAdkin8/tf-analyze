# Auto-generated clean fixture for SEC-GCP-LOG-EXCLUSION-001.
# GCP logging sink with broad exclusion drops audit-relevant entries
# This is a CORRECT configuration; SEC-GCP-LOG-EXCLUSION-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_logging_project_exclusion" "example" {
  name        = "noisy-healthcheck"
  description = "Drop only healthcheck noise"
  filter      = "logName=~\"projects/.*/logs/compute.googleapis.com%2Fhealthcheck\""
}
