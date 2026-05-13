# Clean baseline for SEC-K8S-HELM-003.
# `version` pinned, `verify = true`, keyring referenced — the rule must NOT fire.

resource "helm_release" "signed_pinned" {
  name       = "app"
  repository = "https://charts.example.io"
  chart      = "app"
  version    = "1.4.2"
  verify     = true
  keyring    = "/etc/helm/keyring.gpg"
}
