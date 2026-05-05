# Expected findings:
#  - ROB-VERSION-002 LOW — submodule has .tf files but no required_version declared

variable "name" {
  type = string
}

resource "google_storage_bucket" "x" {
  name     = var.name
  location = "US"
}

output "url" {
  value = google_storage_bucket.x.url
}
