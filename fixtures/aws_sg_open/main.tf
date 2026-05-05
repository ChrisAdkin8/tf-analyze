# Expected findings:
#  - SEC-AWS-SG-001 HIGH — security group allows ingress from 0.0.0.0/0

resource "aws_security_group" "open" {
  name        = "open-sg"
  description = "Allows all inbound traffic"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Restricted SG - OK, no finding
resource "aws_security_group" "restricted" {
  name        = "restricted-sg"
  description = "VPC internal only"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
