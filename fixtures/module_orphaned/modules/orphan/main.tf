# Expected findings:
#  - MOD-UNUSED-001 LOW — this module declares vars + outputs but is
#    never referenced from scenarios/dev (or anywhere else in scope).

variable "name" {
  type        = string
  description = "Resource name"
}

output "id" {
  value = "orphaned-${var.name}"
}
