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

# A release that sets the hardened values (and one whose drop list comes
# from a variable, which is unknown here) must not fire either.
resource "helm_release" "hardened" {
  name       = "hardened"
  chart      = "app"
  repository = "https://charts.example.com"
  version    = "1.2.3"

  set {
    name  = "securityContext.runAsNonRoot"
    value = "true"
  }
  set {
    name  = "securityContext.readOnlyRootFilesystem"
    value = true
  }
  set {
    name  = "securityContext.capabilities.drop"
    value = "{ALL}"
  }
}

variable "drop_caps" {
  type    = string
  default = "{ALL}"
}

resource "helm_release" "from_var" {
  name       = "from-var"
  chart      = "app"
  repository = "https://charts.example.com"
  version    = "1.2.3"

  set {
    name  = "securityContext.capabilities.drop"
    value = var.drop_caps
  }
}
