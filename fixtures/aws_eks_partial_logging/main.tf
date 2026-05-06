# Expected findings: STK-AWS-EKS-005

# enabled_cluster_log_types is set but missing "audit" and "authenticator".
# STK-AWS-EKS-002 does NOT fire (arg is present); STK-AWS-EKS-005 fires twice.
resource "aws_eks_cluster" "partial_logging" {
  name     = "demo-partial-logging"
  role_arn = "arn:aws:iam::123456789012:role/eks-role"

  vpc_config {
    subnet_ids = ["subnet-aaa", "subnet-bbb"]
  }

  enabled_cluster_log_types = ["api", "controllerManager", "scheduler"]
  # Missing: "audit", "authenticator"
}
