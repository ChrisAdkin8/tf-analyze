# Expected findings:
#  - SEC-AWS-DOCDB-001 HIGH — DocumentDB storage not encrypted

resource "aws_docdb_cluster" "main" {
  cluster_identifier      = "main"
  engine                  = "docdb"
  master_username         = "admin"
  master_password         = var.password
  backup_retention_period = 7
  storage_encrypted       = false
}
