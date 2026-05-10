# Expected findings:
#  - SEC-USERDATA-001 HIGH — ${var.password} interpolated in user_data heredoc

variable "password" {
  type      = string
  default   = "hunter2"
  sensitive = true
}

resource "aws_instance" "app" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD=${var.password}
    /opt/app/start.sh
  EOF
}
