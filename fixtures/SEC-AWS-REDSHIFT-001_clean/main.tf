resource "aws_redshift_cluster" "example" {
  cluster_identifier = "tf-redshift"
  database_name      = "mydb"
  master_username    = "admin"
  master_password    = var.db_password
  node_type          = "dc1.large"
  cluster_type       = "single-node"
  encrypted          = true
  kms_key_id         = aws_kms_key.redshift.arn
}
