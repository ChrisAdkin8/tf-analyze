variable "name" {
  type        = string
  description = "Resource name"
}

output "id" {
  value = "used-${var.name}"
}
