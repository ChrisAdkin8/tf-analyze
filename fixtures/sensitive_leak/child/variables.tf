# The child module's variable is missing `sensitive = true`, so the
# sensitivity marker is silently dropped at the module boundary.
variable "child_secret" {
  type        = string
  description = "A secret passed from the parent"
  # finding: should be sensitive = true to preserve the marker
}
