resource "kubernetes_namespace" "app" {
  metadata {
    name = "app"
    # No labels — Pod Security Admission level is unset; default is no enforcement.
  }
}
