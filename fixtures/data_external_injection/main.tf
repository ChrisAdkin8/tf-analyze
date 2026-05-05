# Expected findings:
#  - SEC-DATASOURCE-002 HIGH — data.external program uses variable interpolation (command injection risk)

variable "user_input" {
  type = string
}

data "external" "lookup" {
  program = ["bash", "-c", "echo ${var.user_input}"]
}

output "result" {
  value = data.external.lookup.result
}
