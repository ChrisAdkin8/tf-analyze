resource "kubernetes_service_account" "explicit_automount" {
  metadata {
    name      = "explicit-automount"
    namespace = "app"
  }
  # Explicit opt-in — token mounts on every pod under this SA.
  automount_service_account_token = true
}

resource "kubernetes_service_account" "omitted" {
  metadata {
    name      = "omitted"
    namespace = "app"
  }
  # No automount_service_account_token — Kubernetes default is true,
  # so the token still mounts on every pod under this SA.
}
