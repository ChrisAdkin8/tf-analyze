# Clean fixture: every credential-shaped variable carries sensitive=true,
# and identifier-shaped variables that aren't credentials are ignored.

variable "db_password" {
  type        = string
  sensitive   = true
  description = "DB password — supplied via TF_VAR_db_password or a secrets-manager data source."
}

variable "github_token" {
  type      = string
  sensitive = true
}

variable "stripe_api_key" {
  type        = string
  sensitive   = true
  description = "Stripe key for the prod billing service."
}

# Identifier-shaped names — not credential material, no sensitive=true required.
variable "kms_key_arn" {
  type        = string
  description = "KMS key ARN — identifier, not secret material"
}

variable "secret_id" {
  type        = string
  description = "AWS Secrets Manager secret ID"
}
