resource "aws_db_instance" "old_mysql" {
  identifier        = "demo-old-mysql"
  engine            = "mysql"
  engine_version    = "5.6.51"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  password          = "PlaceholderPass1!"
  skip_final_snapshot = true
}
