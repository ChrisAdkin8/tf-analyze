# Expected findings:
#  - STK-GCP-DATAFLOW-001 MEDIUM — no ip_configuration (defaults to public)

resource "google_dataflow_job" "no_priv" {
  name              = "etl"
  template_gcs_path = "gs://dataflow-templates/latest/Word_Count"
  temp_gcs_location = "gs://example/temp"
}
