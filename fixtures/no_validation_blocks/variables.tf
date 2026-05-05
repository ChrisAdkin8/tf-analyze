# Expected findings:
#  - R-NNN MEDIUM — var.region accepts any string; no regex validation
#  - R-NNN MEDIUM — var.cron accepts any string; no cron-shape validation
#  - R-NNN MEDIUM — var.machine_type has bare `any` type and no validation
#  - Y-NNN LOW — var.cron missing description

variable "region" {
  type    = string
  default = "us-central1"
  # finding: no validation block
}

variable "cron" {
  type    = string
  default = "0 6 * * *"
  # finding: no description
  # finding: no validation block
}

variable "machine_type" {
  type        = any # finding: bare `any`
  description = "Cloud Build worker machine type"
  default     = "e2-standard-2"
  # finding: no validation block
}
