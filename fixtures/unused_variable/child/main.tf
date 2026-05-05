variable "name" {
  type = string
}

resource "google_storage_bucket" "child" {
  name     = var.name
  location = "US"
}

output "bucket_url" {
  value = google_storage_bucket.child.url
}

output "orphan_output" {
  value = google_storage_bucket.child.self_link
}
