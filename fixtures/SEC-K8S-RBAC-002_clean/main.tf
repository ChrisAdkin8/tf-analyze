# Clean baseline for SEC-K8S-RBAC-002.
# Subjects are ServiceAccounts in the workload namespace — never a
# broad system Group — so the rule must NOT fire.

resource "kubernetes_role_binding" "scoped" {
  metadata {
    name      = "app-scoped"
    namespace = "app"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "view"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "app"
    namespace = "app"
  }
}

resource "kubernetes_cluster_role_binding" "platform_readonly" {
  metadata {
    name = "platform-readonly"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "view"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "platform-readonly"
    namespace = "platform"
  }
}
