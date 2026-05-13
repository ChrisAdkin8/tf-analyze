resource "kubernetes_cluster_role_binding" "ops_team_admin" {
  metadata {
    name = "ops-team-admin"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "view"
  }
  # Subject is system:masters — every kubeconfig in that group
  # bypasses RBAC entirely and is treated as cluster-admin.
  subject {
    kind = "Group"
    name = "system:masters"
  }
}

resource "kubernetes_role_binding" "metrics_unauth" {
  metadata {
    name      = "metrics-unauth"
    namespace = "monitoring"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "view"
  }
  # Subject is system:unauthenticated — reachable by any pod that
  # can talk to the API server without a service-account token.
  subject {
    kind = "Group"
    name = "system:unauthenticated"
  }
}
