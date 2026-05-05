# IAM section — exercises SEC-IAM-001/002/003 and SEC-AZURE-RBAC-001.

# SEC-IAM-001 HIGH — project-level grant of an admin role.
resource "google_project_iam_member" "admin_too_broad" {
  project = "demo-project"
  role    = "roles/owner"
  member  = "user:admin@example.com"
}

# SEC-IAM-002 CRITICAL — public binding of a bucket.
resource "google_storage_bucket_iam_member" "public" {
  bucket = "demo-public-bucket"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# SEC-IAM-003 HIGH — same member at project AND resource level
# (project grant supersedes resource grant — redundant, over-broad).
resource "google_project_iam_member" "app_at_project" {
  project = "demo-project"
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:app@demo-project.iam.gserviceaccount.com"
}

resource "google_storage_bucket_iam_member" "app_at_bucket" {
  bucket = "demo-data"
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:app@demo-project.iam.gserviceaccount.com"
}

# SEC-AZURE-RBAC-001 HIGH — role assignment scoped at subscription.
data "azurerm_subscription" "primary" {}

resource "azurerm_role_assignment" "subscription_owner" {
  scope                = data.azurerm_subscription.primary.id
  role_definition_name = "Contributor"
  principal_id         = "00000000-0000-0000-0000-000000000000"
}
