variables {
  project_id = "test-project"
}

run "bucket_name_includes_project_id" {
  command = plan

  assert {
    condition     = google_storage_bucket.data.name == "test-project-data"
    error_message = "bucket name should be ${var.project_id}-data"
  }
}
