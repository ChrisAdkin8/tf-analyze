# Auto-generated clean fixture for STK-AWS-EKS-003.
# EKS cluster Kubernetes Secrets not encrypted with KMS
# This is a CORRECT configuration; STK-AWS-EKS-003 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_eks_cluster" "example" {
  name     = "example"
  role_arn = aws_iam_role.eks.arn
  encryption_config {
    provider { key_arn = aws_kms_key.eks.arn }
    resources = ["secrets"]
  }
  vpc_config { subnet_ids = var.subnet_ids }
}
