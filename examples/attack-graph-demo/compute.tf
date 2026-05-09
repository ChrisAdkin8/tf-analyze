# Public EC2 with IMDSv1 enabled and an attached IAM instance profile.
# This is the pivot node on the attack graph — once an attacker hits
# this instance via the ALB or the SSH-open SG, they grab the role's
# credentials from IMDS and use them against the crown jewels.

resource "aws_instance" "web" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.web.id]
  iam_instance_profile        = aws_iam_instance_profile.web.name

  # metadata_options omitted on purpose → IMDSv1 enabled by default →
  # SSRF on the web app gives an attacker the role's credentials.
  # Fires SEC-AWS-EC2-IMDSV1.

  user_data = <<-EOT
    #!/bin/bash
    yum install -y nginx
    systemctl enable nginx --now
  EOT

  tags = { Name = "${var.app_name}-web" }
}

# IAM instance profile — the link from EC2 to the over-broad role.
resource "aws_iam_instance_profile" "web" {
  name = "${var.app_name}-web-profile"
  role = aws_iam_role.web.name
}
