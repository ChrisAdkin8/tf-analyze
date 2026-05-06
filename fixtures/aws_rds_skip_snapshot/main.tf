# Expected findings:
#  - ROB-AWS-RDS-002 HIGH — RDS instance skips final snapshot on deletion

resource "aws_db_instance" "skip_snapshot" {
  identifier          = "skip-snapshot-db"
  engine              = "postgres"
  engine_version      = "15.3"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "changeme123!"
  skip_final_snapshot = true
}
