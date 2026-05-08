# Auto-generated clean fixture for SEC-K8S-NETPOL-001.
# kubernetes_network_policy absent for the corpus
# This is a CORRECT configuration; SEC-K8S-NETPOL-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "kubernetes_network_policy" "default_deny" {
  metadata {
    name      = "default-deny"
    namespace = kubernetes_namespace.app.metadata[0].name
  }
  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}
