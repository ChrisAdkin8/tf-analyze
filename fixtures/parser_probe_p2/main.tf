# Parser-migration probe P2 — see tasks/hcl-parser-migration.md §1 and Appendix A.
variable "open" {
  default = ["0.0.0.0/0"]
}
resource "aws_security_group" "sg" {
  name = "sg"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = var.open
  }
}
