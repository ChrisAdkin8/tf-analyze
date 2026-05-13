# Auto-generated clean fixture for STK-GCP-DATAPROC-001.
# GCP Dataproc cluster missing autoscaling policy
# This is a CORRECT configuration; STK-GCP-DATAPROC-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_dataproc_cluster" "example" {
  name   = "example"
  region = "us-central1"
  cluster_config {
    autoscaling_config {
      policy_uri = google_dataproc_autoscaling_policy.example.id
    }
  }
}
