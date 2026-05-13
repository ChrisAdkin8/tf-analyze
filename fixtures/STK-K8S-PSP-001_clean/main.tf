# Clean baseline for STK-K8S-PSP-001.
# PSP replaced by Pod Security Admission labels on the namespace —
# the rule must NOT fire.

resource "kubernetes_namespace" "psa_replaces_psp" {
  metadata {
    name = "app"
    labels = {
      "pod-security.kubernetes.io/enforce"         = "restricted"
      "pod-security.kubernetes.io/enforce-version" = "latest"
      "pod-security.kubernetes.io/warn"            = "restricted"
      "pod-security.kubernetes.io/audit"           = "restricted"
    }
  }
}
