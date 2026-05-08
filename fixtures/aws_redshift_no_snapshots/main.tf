# Expected findings:
#  - ROB-AWS-REDSHIFT-001 MEDIUM — automated snapshots disabled

resource "aws_redshift_cluster" "main" {
  cluster_identifier                  = "main"
  database_name                       = "analytics"
  master_username                     = "admin"
  master_password                     = var.password
  node_type                           = "dc2.large"
  cluster_type                        = "single-node"
  encrypted                           = true
  kms_key_id                          = aws_kms_key.redshift.arn
  automated_snapshot_retention_period = 0
}
