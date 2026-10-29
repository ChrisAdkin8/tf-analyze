# Expected findings:
# - SEC-K8S-PSA-001 MEDIUM helm_release.run_as_root (runAsNonRoot = false)
# - SEC-K8S-PSA-001 MEDIUM helm_release.writable_rootfs (readOnlyRootFilesystem = false)
# - SEC-K8S-PSA-001 MEDIUM helm_release.keeps_caps (capabilities.drop without ALL)
#
# One release per helm_set_value pattern, so a test can check that each
# pattern fires on its own (the three once had no `regex:` and never did).

resource "helm_release" "run_as_root" {
  name       = "run-as-root"
  chart      = "app"
  repository = "https://charts.example.com"
  version    = "1.2.3"

  set {
    name  = "securityContext.runAsNonRoot"
    value = "false"
  }
}

resource "helm_release" "writable_rootfs" {
  name       = "writable-rootfs"
  chart      = "app"
  repository = "https://charts.example.com"
  version    = "1.2.3"

  set {
    name  = "securityContext.readOnlyRootFilesystem"
    value = false
  }
}

resource "helm_release" "keeps_caps" {
  name       = "keeps-caps"
  chart      = "app"
  repository = "https://charts.example.com"
  version    = "1.2.3"

  set {
    name  = "securityContext.capabilities.drop"
    value = "{NET_RAW}"
  }
}
