# Auto-generated clean fixture for SEC-K8S-PSA-001.
# kubernetes_namespace missing Pod Security Admission label
# This is a CORRECT configuration; SEC-K8S-PSA-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "kubernetes_namespace" "example" {
  metadata {
    name = "example"
    labels = {
      "pod-security.kubernetes.io/enforce"         = "restricted"
      "pod-security.kubernetes.io/enforce-version" = "latest"
    }
  }
}
