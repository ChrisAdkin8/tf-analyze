# Parser-migration probe P6 — see tasks/hcl-parser-migration.md §1 and Appendix A.
resource "aws_security_group" "sg" {
  name = "sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
