resource "aws_neptune_cluster" "example" {
  cluster_identifier  = "neptune-cluster"
  engine              = "neptune"
  storage_encrypted   = true
  kms_key_arn         = aws_kms_key.neptune.arn
  skip_final_snapshot = true
}
