resource "aws_eks_cluster" "example" {
  name     = "example-cluster"
  role_arn = aws_iam_role.cluster.arn

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  vpc_config {
    subnet_ids = ["subnet-abc", "subnet-def"]
  }
}
