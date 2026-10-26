resource "kubernetes_cluster_role_binding_v1" "readers" {
  metadata {
    name = "platform-readers"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "view"
  }

  subject {
    kind      = "Group"
    name      = "platform-readers"
    api_group = "rbac.authorization.k8s.io"
  }
}
