# Expected findings:
#  - ROB-UNUSED-001 LOW — unused_tag is declared but never referenced
#  - ROB-UNUSED-002 LOW — orphan_output is never consumed by a caller

variable "project_id" {
  type = string
}

variable "unused_tag" {
  type        = string
  description = "This variable is declared but never used anywhere."
  default     = "oops"
}
