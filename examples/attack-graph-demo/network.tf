# Public-facing networking. The ALB and the EC2 SG are both internet-
# reachable on the attack graph; the data-tier SG is internal-only.

resource "aws_vpc" "demo" {
  cidr_block           = "10.50.0.0/16"
  enable_dns_hostnames = true

  tags = { Name = "${var.app_name}-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.demo.id
  cidr_block              = "10.50.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = { Name = "${var.app_name}-public" }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.demo.id
  cidr_block        = "10.50.10.0/24"
  availability_zone = "us-east-1a"

  tags = { Name = "${var.app_name}-private" }
}

resource "aws_internet_gateway" "demo" {
  vpc_id = aws_vpc.demo.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.demo.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.demo.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Public-facing ALB — internet-reachable on port 443.
resource "aws_lb" "public_alb" {
  name               = "${var.app_name}-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = [aws_subnet.public.id]
  security_groups    = [aws_security_group.alb.id]

  # access_logs intentionally omitted — fires SEC-AWS-ALB-001
}

# ALB security group — open to the world on 443.
resource "aws_security_group" "alb" {
  name        = "${var.app_name}-alb-sg"
  description = "ALB ingress"
  vpc_id      = aws_vpc.demo.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Web-tier security group — open to the world on 80 (the misconfig).
resource "aws_security_group" "web" {
  name        = "${var.app_name}-web-sg"
  description = "Web tier ingress"
  vpc_id      = aws_vpc.demo.id

  # Anti-pattern: SSH-from-anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Data-tier security group — only the web tier can reach it.
# Internal-only by design; the attack path enters via the web SG.
resource "aws_security_group" "data" {
  name        = "${var.app_name}-data-sg"
  description = "Data tier ingress (internal-only)"
  vpc_id      = aws_vpc.demo.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }
}
