resource "aws_eks_cluster" "no_logging" {
  name     = "demo-no-logging"
  role_arn = "arn:aws:iam::123456789012:role/eks-cluster-role"

  vpc_config {
    subnet_ids = ["subnet-12345678"]
  }

  # enabled_cluster_log_types intentionally absent — API audit trail and
  # control-plane events are not shipped to CloudWatch.
}
