# variables.tf — variables split into a separate file (the canonical
# real-world layout). Cross-file resolution must walk both files to
# decide whether `var.X` references resolve to a literal default.

variable "encrypted" {
  type    = bool
  default = false   # Drives the rule below — should be picked up despite living in a different file.
}

variable "unused_in_resource" {
  type        = string
  description = "Declared here but never referenced. ROB-UNUSED-001 should fire."
  default     = "x"
}
