# Auto-generated clean fixture for SEC-K8S-RBAC-001.
# ClusterRoleBinding grants cluster-admin
# This is a CORRECT configuration; SEC-K8S-RBAC-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

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
