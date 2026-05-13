# Clean baseline for SEC-K8S-HELM-004.
# Neither bypass flag set — webhooks and CRDs run normally. The rule
# must NOT fire.

resource "helm_release" "safe" {
  name             = "app"
  repository       = "https://charts.example.io"
  chart            = "app"
  version          = "1.4.2"
  disable_webhooks = false
  skip_crds        = false
  wait             = true
  wait_for_jobs    = true
  timeout          = 600
}
