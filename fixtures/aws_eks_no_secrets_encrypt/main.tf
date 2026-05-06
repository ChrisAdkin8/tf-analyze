resource "aws_eks_cluster" "no_secrets_encrypt" {
  name     = "demo-no-encrypt"
  role_arn = "arn:aws:iam::123456789012:role/eks-cluster-role"

  vpc_config {
    subnet_ids = ["subnet-12345678"]
  }

  # encryption_config block absent — Kubernetes Secrets are stored in etcd
  # with only EBS-level (AWS-managed) encryption.
}
