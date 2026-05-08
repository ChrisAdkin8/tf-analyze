# Multi-region setup with provider aliases. Each aliased provider
# block must be scanned independently.

provider "aws" {
  alias  = "us"
  region = "us-east-1"
}

provider "aws" {
  alias                   = "eu"
  region                  = "eu-west-1"
  skip_credentials_validation = true   # SEC-AWS-PROVIDER-001 territory if/when that ships
}
