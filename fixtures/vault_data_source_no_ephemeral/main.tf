# Expected findings:
#  - SEC-EPHEMERAL-001 MEDIUM — Vault secret data source persists to state

terraform {
  required_version = ">= 1.10.0"
}

data "vault_kv_secret_v2" "db_password" {
  mount = "secret"
  name  = "app/db"
}

resource "google_sql_user" "app" {
  name     = "app"
  instance = "main"
  password = data.vault_kv_secret_v2.db_password.data["password"]
}
