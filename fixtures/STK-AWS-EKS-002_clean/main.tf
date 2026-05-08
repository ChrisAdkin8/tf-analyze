# Auto-generated clean fixture for STK-AWS-EKS-002.
# EKS cluster control plane logging not enabled
# This is a CORRECT configuration; STK-AWS-EKS-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_eks_cluster" "example" {
  # ... other arguments ...
  enabled_cluster_log_types = [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ]
}
