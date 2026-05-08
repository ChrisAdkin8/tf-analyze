# Expected findings:
#  - SEC-AWS-REDSHIFT-001 HIGH — Redshift cluster not encrypted

resource "aws_redshift_cluster" "main" {
  cluster_identifier = "main"
  database_name      = "analytics"
  master_username    = "admin"
  master_password    = var.password
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  encrypted          = false
}
