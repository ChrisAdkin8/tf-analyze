# Auto-generated clean fixture for ROB-AWS-REDSHIFT-001.
# Redshift cluster has no automated snapshot retention
# This is a CORRECT configuration; ROB-AWS-REDSHIFT-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_redshift_cluster" "example" {
  cluster_identifier                  = "example"
  automated_snapshot_retention_period = 7
}
