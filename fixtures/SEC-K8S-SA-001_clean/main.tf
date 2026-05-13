# Clean baseline for SEC-K8S-SA-001.
# automount_service_account_token = false — pods that need API access
# must opt back in explicitly at the Pod spec. The rule must NOT fire.

resource "kubernetes_service_account" "deny_by_default" {
  metadata {
    name      = "app"
    namespace = "app"
  }
  automount_service_account_token = false
}
