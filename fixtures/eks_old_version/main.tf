# Expected findings:
#  - STK-K8S-VERSION-001 HIGH — EKS pinned to 1.25 (older than N-2)

resource "aws_eks_cluster" "primary" {
  name     = "primary"
  version  = "1.25"
  role_arn = "arn:aws:iam::123:role/eks"

  vpc_config {
    subnet_ids = ["subnet-aaa", "subnet-bbb"]
  }
}
