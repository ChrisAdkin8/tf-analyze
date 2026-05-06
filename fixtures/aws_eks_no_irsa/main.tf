resource "aws_eks_cluster" "no_irsa" {
  name     = "demo-no-irsa"
  role_arn = "arn:aws:iam::123456789012:role/eks-cluster-role"

  vpc_config {
    subnet_ids = ["subnet-12345678"]
  }
}

# No aws_iam_openid_connect_provider resource — IRSA is not configured.
# Pods inherit the node group IAM role instead of per-pod scoped roles.
