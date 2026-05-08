# Auto-generated clean fixture for ROB-AWS-RDS-003.
# RDS instance or Aurora cluster missing deletion protection
# This is a CORRECT configuration; ROB-AWS-RDS-003 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_db_instance" "example" {
  # ... other arguments ...
  deletion_protection = true
}
