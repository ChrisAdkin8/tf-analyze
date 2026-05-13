# Clean baseline for SEC-K8S-SECRET-002.
# Image-pull credential pulled via ExternalSecret from Vault; no
# literal .dockerconfigjson in source or state. The rule must NOT fire.

resource "kubernetes_manifest" "image_pull_secret" {
  manifest = {
    apiVersion = "external-secrets.io/v1beta1"
    kind       = "ExternalSecret"
    metadata = {
      name      = "pull-creds"
      namespace = "app"
    }
    spec = {
      secretStoreRef = {
        name = "vault"
        kind = "ClusterSecretStore"
      }
      target = {
        name           = "pull-creds"
        creationPolicy = "Owner"
        template = {
          type = "kubernetes.io/dockerconfigjson"
        }
      }
      data = [{
        secretKey = ".dockerconfigjson"
        remoteRef = {
          key      = "kv/data/registry"
          property = "dockerconfigjson"
        }
      }]
    }
  }
}
