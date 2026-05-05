# Expected findings: NONE
# Guards against: SEC-EPHEMERAL-001
#
# SEC-EPHEMERAL-001 only applies on TF 1.10+ (where ephemeral resources
# exist). When required_version pins below 1.10, the rule must not fire
# even though the vault_kv_secret_v2 data source is present — the
# user has no migration target available.

terraform {
  required_version = ">= 1.5.0, < 1.10.0"
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
