# Auto-generated clean fixture for STK-AWS-RDS-004.
# RDS instance uses end-of-life database engine version
# This is a CORRECT configuration; STK-AWS-RDS-004 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_db_instance" "example" {
  engine         = "postgres"
  engine_version = "16.2"
  instance_class = "db.t3.medium"
  username       = "admin"
  password       = var.db_password
}
