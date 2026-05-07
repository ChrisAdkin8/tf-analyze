variable "enable_mfa" {
  description = "Must be true for production deployments. MFA is required."
  type        = bool
  default     = false
}
