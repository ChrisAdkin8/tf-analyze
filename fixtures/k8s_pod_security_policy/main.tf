resource "kubernetes_pod_security_policy" "restricted" {
  metadata {
    name = "restricted"
  }
  spec {
    privileged                 = false
    allow_privilege_escalation = false
    required_drop_capabilities = ["ALL"]
    volumes                    = ["configMap", "emptyDir", "projected", "secret", "persistentVolumeClaim"]
    run_as_user {
      rule = "MustRunAsNonRoot"
    }
    se_linux {
      rule = "RunAsAny"
    }
    fs_group {
      rule = "MustRunAs"
      range {
        min = 1
        max = 65535
      }
    }
  }
}
