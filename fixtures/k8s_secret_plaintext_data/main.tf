resource "kubernetes_secret" "db_credentials" {
  metadata {
    name      = "db-credentials"
    namespace = "app"
  }
  # Literal data — the value lands in terraform state and any .tf
  # files that reference it. base64 is encoding, not encryption.
  data = {
    username = "admin"
    password = "SuperSecret123!"
  }
}
