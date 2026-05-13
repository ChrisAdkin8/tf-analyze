# Clean baseline for STK-K8S-PSA-002.
# enforce is `restricted` (not `privileged`) and `warn`/`audit` are
# wired alongside — the rule must NOT fire.

resource "kubernetes_namespace" "hardened" {
  metadata {
    name = "hardened"
    labels = {
      "pod-security.kubernetes.io/enforce"         = "restricted"
      "pod-security.kubernetes.io/enforce-version" = "latest"
      "pod-security.kubernetes.io/warn"            = "restricted"
      "pod-security.kubernetes.io/audit"           = "restricted"
    }
  }
}
