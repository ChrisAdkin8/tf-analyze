# Auto-generated clean fixture for ROB-AWS-RDS-002.
# RDS instance or Aurora cluster skips final snapshot on deletion
# This is a CORRECT configuration; ROB-AWS-RDS-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_db_instance" "example" {
  # ... other arguments ...
  skip_final_snapshot       = false
  final_snapshot_identifier = "final-snapshot-${replace(timestamp(), ":", "-")}"
}
