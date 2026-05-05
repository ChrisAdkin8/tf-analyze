# Secrets section — exercises SEC-EPHEMERAL-001 (only because
# versions.tf pins required_version >= 1.10.0). On older TF this rule
# is correctly skipped by the applies_when.min_terraform gate.

# SEC-EPHEMERAL-001 MEDIUM — Vault data source persists secret to state.
data "vault_kv_secret_v2" "db_password" {
  mount = "secret"
  name  = "app/db"
}

resource "google_sql_user" "app" {
  name     = "app"
  instance = google_sql_database_instance.main.name
  password = data.vault_kv_secret_v2.db_password.data["password"]
}

# SEC-SENSITIVE-001 HIGH — output exposes a sensitive variable without
# being marked sensitive=true.
variable "vault_token" {
  type      = string
  sensitive = true
}

output "vault_token_echo" {
  value = var.vault_token
  # sensitive = true intentionally omitted
}
