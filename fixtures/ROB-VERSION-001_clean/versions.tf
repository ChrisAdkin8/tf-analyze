# Clean: a current Terraform floor. "~> 1.10" must not match the
# rule's "1.[0-5]" (it used to, via the "1.1" prefix).
terraform {
  required_version = "~> 1.10"
}
