# Expected findings:
#  - SEC-USERDATA-002 MEDIUM — var.secret assigned straight to user_data

variable "secret" {
  type      = string
  sensitive = true
}

resource "aws_instance" "app" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  user_data     = var.secret
}
