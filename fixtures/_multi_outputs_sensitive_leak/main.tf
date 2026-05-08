resource "aws_db_instance" "main" {
  identifier           = "demo"
  password             = var.db_password
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  skip_final_snapshot  = false
  storage_encrypted    = true
}
