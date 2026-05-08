# Sensitive variable referenced from a non-sensitive output → leak.
# SEC-SENSITIVE-001 must fire even though variables.tf and outputs.tf
# live in different files.

output "db_endpoint" {
  value = aws_db_instance.main.endpoint
}

output "db_password_leak" {
  value = var.db_password   # missing `sensitive = true` — leaks to state and logs.
}
