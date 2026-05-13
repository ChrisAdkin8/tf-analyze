resource "kubernetes_ingress_v1" "plaintext" {
  metadata {
    name      = "plaintext"
    namespace = "app"
  }
  spec {
    # No tls{} block — every host below is reachable over HTTP only.
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
