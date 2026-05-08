# Auto-generated clean fixture for STK-AWS-EKS-001.
# EKS cluster API endpoint private access not enabled
# This is a CORRECT configuration; STK-AWS-EKS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_eks_cluster" "example" {
  name     = "example"
  role_arn = aws_iam_role.eks.arn
  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
  }
}
