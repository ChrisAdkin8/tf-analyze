resource "aws_db_instance" "main" {
  identifier           = "prod-db"
  engine               = "mysql"
  instance_class       = "db.t3.medium"
  allocated_storage    = 20
  username             = "admin"
  password             = "placeholder"
  deletion_protection  = false

  tags = {
    Environment = "production"
  }
}
