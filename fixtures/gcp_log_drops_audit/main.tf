# Expected findings:
#  - SEC-GCP-LOG-EXCLUSION-001 HIGH — exclusion drops cloudaudit logs

resource "google_logging_project_exclusion" "drop_audit" {
  name        = "drop-audit"
  description = "REMOVE: dropping audit logs hides admin activity"
  filter      = "logName=~\"projects/example/logs/cloudaudit.googleapis.com%2Factivity\""
}
