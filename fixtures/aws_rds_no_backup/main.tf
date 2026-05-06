# Expected findings:
#  - ROB-AWS-RDS-001 HIGH — RDS instance backup retention disabled

resource "aws_db_instance" "no_backup" {
  identifier               = "no-backup-db"
  engine                   = "mysql"
  engine_version           = "8.0"
  instance_class           = "db.t3.micro"
  allocated_storage        = 20
  username                 = "admin"
  password                 = "changeme123!"
  backup_retention_period  = 0
  skip_final_snapshot      = true
}
