# Expected findings:
#  - SEC-SECRETS-001 CRITICAL — hardcoded password / API key in Terraform source

resource "aws_db_instance" "app" {
  identifier     = "app-db"
  engine         = "mysql"
  instance_class = "db.t3.micro"
  username       = "admin"
  password       = "Sup3rS3cretP@ss!"
}

resource "google_sql_database_instance" "main" {
  name             = "main"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = false
    }
  }

  root_password = "hardcoded-root-password-123"
}
