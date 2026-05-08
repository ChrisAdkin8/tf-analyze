resource "helm_release" "exposed" {
  name       = "exposed"
  repository = "https://charts.example.io"
  chart      = "example"

  set {
    name  = "service.type"
    value = "LoadBalancer"
  }
}
