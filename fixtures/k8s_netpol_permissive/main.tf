resource "kubernetes_network_policy" "egress_wildcard" {
  metadata {
    name      = "egress-wildcard"
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
          # The whole point of a NetworkPolicy is to scope egress —
          # whitelisting the entire internet defeats it.
          cidr = "0.0.0.0/0"
        }
      }
    }
  }
}

resource "kubernetes_network_policy" "empty_egress" {
  metadata {
    name      = "empty-egress"
    namespace = "app"
  }
  spec {
    pod_selector {
      match_labels = {
        app = "other"
      }
    }
    policy_types = ["Egress"]
    # Empty egress rule == "allow all egress" in NetworkPolicy semantics.
    # The operator probably meant "deny all egress" — but that's expressed
    # via `policy_types = ["Egress"]` with no `egress { }` block at all.
    egress {
    }
  }
}
