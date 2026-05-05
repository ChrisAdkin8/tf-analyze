# OWASP A03:2021 — Injection
# Cloud: AWS
#
# AWS-shaped injection vectors in Terraform:
#
#   1. EC2 `user_data` constructed from unvalidated tfvars — runs as
#      root on the instance at first boot. A malicious value lands
#      in the cloud-init shell script.
#   2. Lambda environment variable forwarded to a downstream shell
#      via a Lambda function that calls os.system / shell-out.
#   3. `null_resource` with `local-exec` shelling out with
#      interpolated tfvars.
#   4. `aws_lambda_function.filename` pointing at an arbitrary path
#      (uncommon, but a build-time injection vector).
#
# Real-world impact:
#   - 2017+ wave of cryptocurrency miners deployed via user_data
#     injection on misconfigured Terraform Cloud workspaces.
#   - Lambda env-var injection via misconfigured API Gateway has been
#     used for credential harvesting.
#
# Expected tf-analyze findings:
#   - SEC-PROVISIONER-001  HIGH    Provisioner block used for shell execution
#
# Fix summary: keep user_data and provisioners out of unvalidated
# tfvar paths; if a value reaches a shell, validate via the variable
# `validation` block first.

variable "instance_name" {
  description = "EC2 instance name"
  type        = string
}

# user_data interpolates an unvalidated tfvar. An attacker who
# controls tfvars (e.g. a malicious PR adding a default) gets RCE on
# the instance at first boot.
resource "aws_instance" "ec2_user_data_injection" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  user_data = <<-EOT
    #!/bin/bash
    echo "configuring ${var.instance_name}"
    /usr/local/bin/configure ${var.instance_name}
  EOT
}

# null_resource provisioner with shell-out — same anti-pattern as the
# GCP variant.
resource "null_resource" "shell_inject" {
  provisioner "local-exec" {
    command = "aws s3 cp s3://demo-bucket/${var.instance_name}.cfg /tmp/"
  }
}
