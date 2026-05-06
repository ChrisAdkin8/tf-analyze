# Expected findings:
#  - SEC-AWS-RDS-002 HIGH — RDS instance storage not encrypted

resource "aws_db_instance" "unencrypted" {
  identifier          = "unencrypted-db"
  engine              = "postgres"
  engine_version      = "15.3"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "changeme123!"
  storage_encrypted   = false
  skip_final_snapshot = true
}
