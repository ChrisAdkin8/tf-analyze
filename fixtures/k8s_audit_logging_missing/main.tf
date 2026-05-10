# Expected findings:
#  - STK-K8S-AUDIT-POLICY-001 MEDIUM — EKS cluster without enabled_cluster_log_types

resource "aws_eks_cluster" "primary" {
  name     = "primary"
  version  = "1.30"
  role_arn = "arn:aws:iam::123:role/eks"

  vpc_config {
    subnet_ids = ["subnet-aaa", "subnet-bbb"]
  }
}
