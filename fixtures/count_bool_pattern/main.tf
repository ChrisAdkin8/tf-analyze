# Expected findings:
#  - ROB-COUNT-001 LOW — boolean count pattern on resource
#  - ROB-COUNT-001 LOW — boolean count pattern on module

variable "enable_monitoring" {
  type        = bool
  description = "Whether to create monitoring resources"
  default     = false
}

variable "enable_cdn" {
  type        = bool
  description = "Whether to enable CDN"
  default     = false
}

resource "google_monitoring_alert_policy" "cpu" {
  count        = var.enable_monitoring ? 1 : 0
  display_name = "High CPU"
  combiner     = "OR"

  conditions {
    display_name = "CPU > 80%"
    condition_threshold {
      filter          = "metric.type=\"compute.googleapis.com/instance/cpu/utilization\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8
      duration        = "60s"
    }
  }
}

module "cdn" {
  count  = var.enable_cdn ? 1 : 0
  source = "./cdn"
}

# This should NOT fire — for_each is the correct pattern
resource "google_compute_backend_bucket" "static" {
  for_each    = var.enable_cdn ? toset(["this"]) : toset([])
  name        = "static-assets"
  bucket_name = "my-bucket"
}
