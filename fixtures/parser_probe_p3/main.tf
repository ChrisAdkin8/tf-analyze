# Parser-migration probe P3 — see tasks/hcl-parser-migration.md §1 and Appendix A.
resource "aws_vpc_security_group_ingress_rule" "r" {
  security_group_id = "sg-1"
  cidr_ipv4 = "0.0.0.0/0"
  from_port = 22
  to_port = 22
  ip_protocol = "tcp"
}
