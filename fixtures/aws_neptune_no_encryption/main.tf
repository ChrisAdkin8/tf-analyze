# Expected findings:
#  - SEC-AWS-NEPTUNE-001 HIGH — Neptune cluster not encrypted

resource "aws_neptune_cluster" "main" {
  cluster_identifier  = "main"
  engine              = "neptune"
  backup_retention_period = 7
  storage_encrypted   = false
}
