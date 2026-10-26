resource "aws_ssm_parameter" "ami" {
  name  = "/platform/base-ami-id"
  type  = "String"
  value = "ami-0123456789abcdef0"
}
