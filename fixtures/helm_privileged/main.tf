resource "helm_release" "priv" {
  name       = "priv"
  repository = "https://charts.example.io"
  chart      = "example"

  set {
    name  = "securityContext.privileged"
    value = "true"
  }
}
