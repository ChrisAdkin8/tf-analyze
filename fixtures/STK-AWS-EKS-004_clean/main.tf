resource "aws_eks_cluster" "example" {
  name     = "example-cluster"
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    subnet_ids = ["subnet-abc", "subnet-def"]
  }
}

data "tls_certificate" "cluster" {
  url = aws_eks_cluster.example.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "cluster" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cluster.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.example.identity[0].oidc[0].issuer
}
