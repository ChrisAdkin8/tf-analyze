# AWS corpus — provider + Terraform version pinning.
#
# AWS-specific catalogue coverage in tf-analyze is intentionally
# narrower than GCP (3 active SEC rules at the time of writing). The
# corpus focuses on documenting OWASP categories with realistic AWS
# anti-patterns rather than maximising rule fires — many of these
# anti-patterns are flagged today by tfsec/Checkov but not yet by
# tf-analyze, and serve as a roadmap for catalogue expansion.

terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}
