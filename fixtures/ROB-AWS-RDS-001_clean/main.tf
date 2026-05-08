# Auto-generated clean fixture for ROB-AWS-RDS-001.
# RDS instance or Aurora cluster backup retention disabled
# This is a CORRECT configuration; ROB-AWS-RDS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_db_instance" "example" {
  # ... other arguments ...
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
}
