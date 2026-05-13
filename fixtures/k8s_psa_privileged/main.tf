resource "kubernetes_namespace" "permissive" {
  metadata {
    name = "permissive"
    labels = {
      # Setting enforce to "privileged" silences PSA — every container
      # capability, hostPath, hostNetwork, hostPID is permitted.
      # Functionally equivalent to having no label at all, but more
      # insidious because it looks intentional in a code review.
      "pod-security.kubernetes.io/enforce"         = "privileged"
      "pod-security.kubernetes.io/enforce-version" = "latest"
    }
  }
}
