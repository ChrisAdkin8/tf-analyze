# Expected findings:
#  - SEC-AWS-SG-001 CRITICAL — dynamic "ingress" over a variable opens SSH to 0.0.0.0/0
#  - SEC-AWS-SG-001 CRITICAL — the VPC's default security group allows all traffic from 0.0.0.0/0

variable "ingress_rules" {
  default = [
    { port = 443, cidrs = ["10.0.0.0/8"] },
    { port = 22, cidrs = ["0.0.0.0/0"] },
  ]
}

resource "aws_security_group" "app" {
  name = "app"

  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = ingress.value.cidrs
    }
  }
}

resource "aws_default_security_group" "default" {
  vpc_id = "vpc-0123456789abcdef0"

  ingress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}
