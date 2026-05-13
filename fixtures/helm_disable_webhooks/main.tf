resource "helm_release" "webhooks_off" {
  name       = "webhooks-off"
  repository = "https://charts.example.io"
  chart      = "app"
  version    = "1.4.2"
  # Disabling webhooks bypasses admission validation, defaulting, and
  # ordering — the chart's safety net silently rolls off.
  disable_webhooks = true
}

resource "helm_release" "crds_skipped" {
  name       = "crds-skipped"
  repository = "https://charts.example.io"
  chart      = "operator"
  version    = "2.0.1"
  # Skipping CRDs means any subsequent resource that references them
  # races the controller and fails on apply.
  skip_crds = true
}
