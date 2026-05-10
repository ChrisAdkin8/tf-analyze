# Expected findings:
#  - SEC-SENSITIVE-PATTERN-001 HIGH — three credential-shaped vars
#    (db_password, github_token, stripe_api_key) declared without
#    sensitive=true; the value will leak to plan output and CI logs.

variable "db_password" {
  type        = string
  description = "DB password"
}

variable "github_token" {
  type    = string
  default = ""
}

variable "stripe_api_key" {
  type        = string
  description = "Stripe key for the prod billing service"
}

# Negative case: name matches the regex but is correctly marked sensitive.
variable "vault_token" {
  type        = string
  sensitive   = true
  description = "Vault token used by the bootstrap helper."
}

# Negative case: identifier-shaped names that mention 'key' or 'secret'
# but refer to an identifier, not the secret material — must NOT fire.
variable "kms_key_arn" {
  type        = string
  description = "KMS key ARN — identifier, not secret material"
}

variable "secret_id" {
  type        = string
  description = "AWS Secrets Manager secret ID — not the secret value"
}
