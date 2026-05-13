# Clean baseline for SEC-K8S-NETPOL-002.
# Scoped cidr + non-empty rules — the rule must NOT fire.

resource "kubernetes_network_policy" "scoped" {
  metadata {
    name      = "scoped"
    namespace = "app"
  }
  spec {
    pod_selector {
      match_labels = {
        app = "app"
      }
    }
    policy_types = ["Egress"]
    egress {
      to {
        ip_block {
          cidr   = "10.0.0.0/16"
          except = ["10.0.100.0/24"]
        }
      }
      ports {
        protocol = "TCP"
        port     = "5432"
      }
    }
  }
}
