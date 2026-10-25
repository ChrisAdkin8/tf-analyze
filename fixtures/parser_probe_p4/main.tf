# Parser-migration probe P4 — see tasks/hcl-parser-migration.md §1 and Appendix A.
resource "aws_security_group" "sg" {
  name        = "sg"
  description = <<EOT
ingress {
  cidr_blocks = ["0.0.0.0/0"]
}
EOT
}
