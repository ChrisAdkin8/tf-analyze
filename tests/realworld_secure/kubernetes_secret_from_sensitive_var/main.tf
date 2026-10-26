variable "db_password" {
  type        = string
  description = "Database password."
  sensitive   = true
}

resource "kubernetes_secret_v1" "db" {
  metadata {
    name      = "db"
    namespace = "app"
  }

  data = {
    password = var.db_password
  }
}
