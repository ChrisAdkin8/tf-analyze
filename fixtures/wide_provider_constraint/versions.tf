# Expected finding: S-NNN MEDIUM — provider pinned with `>= 6.0` and no upper bound.
# A `>=` constraint allows any future major version, including breaking changes.
# The pessimistic constraint `~> 6.50` (or `~> 6.0`) bounds the major version.

terraform {
  required_version = "~> 1.10"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0" # finding: missing upper bound
    }
    google-beta = {
      source = "hashicorp/google-beta"
      # finding: missing version constraint entirely
    }
  }
}
