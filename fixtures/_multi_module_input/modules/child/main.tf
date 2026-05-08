resource "aws_ebs_volume" "child_data" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = var.encrypted
}
