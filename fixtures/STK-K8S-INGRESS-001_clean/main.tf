# Clean baseline for STK-K8S-INGRESS-001.
# Ingress has a tls{} block + cert-manager annotation — every host
# is reachable over HTTPS. The rule must NOT fire.

resource "kubernetes_ingress_v1" "tls_enabled" {
  metadata {
    name      = "tls-enabled"
    namespace = "app"
    annotations = {
      "cert-manager.io/cluster-issuer" = "letsencrypt-prod"
    }
  }
  spec {
    tls {
      hosts       = ["app.example.com"]
      secret_name = "app-tls"
    }
    rule {
      host = "app.example.com"
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = "app"
              port {
                number = 80
              }
            }
          }
        }
      }
    }
  }
}
