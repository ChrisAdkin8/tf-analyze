# Expected findings:
#  - S-NNN HIGH — output exposes a sensitive value but is not marked sensitive
#  - S-NNN HIGH — sensitive variable passed to module input where the receiving
#                 variable is NOT marked sensitive (sensitivity dropped at boundary)

terraform {
  required_version = "~> 1.10"
}

variable "db_password" {
  type      = string
  sensitive = true
}

# finding: output references a sensitive var without sensitive = true
output "db_password_passthrough" {
  value = var.db_password
}

module "child" {
  source        = "./child"
  child_secret  = var.db_password # finding: sensitive crossing into non-sensitive var
}
