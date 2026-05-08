resource "kubernetes_cluster_role_binding" "ci_admin" {
  metadata {
    name = "ci-admin"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "ci"
    namespace = "ci"
  }
}
