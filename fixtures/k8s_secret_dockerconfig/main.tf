resource "kubernetes_secret" "pull_creds" {
  metadata {
    name      = "pull-creds"
    namespace = "app"
  }
  type = "kubernetes.io/dockerconfigjson"
  # Literal .dockerconfigjson — registry credentials in state. Reading
  # the state file unlocks the entire private container registry,
  # which usually mirrors every internal binary the team ships.
  data = {
    ".dockerconfigjson" = jsonencode({
      auths = {
        "registry.example.io" = {
          username = "ci-bot"
          password = "RegistryS3cret!"
          auth     = "Y2ktYm90OlJlZ2lzdHJ5UzNjcmV0IQ=="
        }
      }
    })
  }
}
