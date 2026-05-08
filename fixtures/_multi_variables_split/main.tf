# main.tf — the resource references var.encrypted (false default).
# detect.py's variable resolution must walk variables.tf to fold the
# default into the rule check.

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = var.encrypted   # → resolves to false → SEC-AWS-EBS-001 fires.
}
