# Expected findings:
#  - STK-GCP-DATAPROC-001 LOW — no autoscaling_config

resource "google_dataproc_cluster" "no_autoscale" {
  name   = "etl"
  region = "us-central1"
  cluster_config {
    master_config {
      num_instances = 1
      machine_type  = "e2-standard-4"
    }
    worker_config {
      num_instances = 4
      machine_type  = "e2-standard-4"
    }
  }
}
