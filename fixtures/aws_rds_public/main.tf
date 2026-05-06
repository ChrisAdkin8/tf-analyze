# Expected findings:
#  - SEC-AWS-RDS-001 HIGH — RDS instance publicly accessible

resource "aws_db_instance" "public" {
  identifier             = "public-db"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "changeme123!"
  publicly_accessible    = true
  skip_final_snapshot    = true
}
