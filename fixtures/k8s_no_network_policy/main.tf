resource "kubernetes_namespace" "app" {
  metadata {
    name = "app"
    labels = {
      "pod-security.kubernetes.io/enforce" = "restricted"
    }
  }
}

# No kubernetes_network_policy anywhere in the corpus → SEC-K8S-NETPOL-001 fires.
