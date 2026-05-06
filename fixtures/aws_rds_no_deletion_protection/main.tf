resource "aws_db_instance" "no_protection" {
  identifier        = "demo-no-protection"
  engine            = "postgres"
  engine_version    = "15.6"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "postgres"
  password          = "PlaceholderPass1!"
  # deletion_protection intentionally absent — accidental destroy is permanent
}
