resource "aws_docdb_cluster" "example" {
  cluster_identifier      = "my-docdb"
  engine                  = "docdb"
  master_username         = "admin"
  master_password         = var.db_password
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.docdb.arn
}
