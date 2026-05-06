resource "aws_eks_cluster" "public_endpoint" {
  name     = "demo-public"
  role_arn = "arn:aws:iam::123456789012:role/eks-cluster-role"

  vpc_config {
    subnet_ids = ["subnet-12345678"]
    # endpoint_private_access absent — defaults to false
    endpoint_public_access = true
  }
}
