# Auto-generated clean fixture for STK-GCP-DATAFLOW-001.
# GCP Dataflow job exposes workers to public IPs
# This is a CORRECT configuration; STK-GCP-DATAFLOW-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_dataflow_job" "example" {
  name              = "etl"
  template_gcs_path = "gs://dataflow-templates/latest/Word_Count"
  temp_gcs_location = "gs://example/temp"
  ip_configuration  = "WORKER_IP_PRIVATE"
  subnetwork        = google_compute_subnetwork.df.id
}
