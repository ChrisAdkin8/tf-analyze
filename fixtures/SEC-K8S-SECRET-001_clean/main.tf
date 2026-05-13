# Clean baseline for SEC-K8S-SECRET-001.
# Secret is declared via External Secrets Operator (ESO) — Terraform
# only declares the *reference*; ESO pulls the literal value from
# Vault at runtime. The rule must NOT fire.

resource "kubernetes_manifest" "db_credentials_external" {
  manifest = {
    apiVersion = "external-secrets.io/v1beta1"
    kind       = "ExternalSecret"
    metadata = {
      name      = "db-credentials"
      namespace = "app"
    }
    spec = {
      secretStoreRef = {
        name = "vault"
        kind = "ClusterSecretStore"
      }
      target = {
        name           = "db-credentials"
        creationPolicy = "Owner"
      }
      data = [{
        secretKey = "password"
        remoteRef = {
          key      = "kv/data/app"
          property = "password"
        }
      }]
    }
  }
}
