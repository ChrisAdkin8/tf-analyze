# Auto-generated clean fixture for STK-GCP-CLOUDSQL-IAMAUTH-001.
# Cloud SQL instance not using IAM authentication
# This is a CORRECT configuration; STK-GCP-CLOUDSQL-IAMAUTH-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_sql_database_instance" "example" {
  name             = "example"
  region           = "us-central1"
  database_version = "POSTGRES_16"
  settings {
    tier = "db-custom-2-7680"
    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }
  }
}
