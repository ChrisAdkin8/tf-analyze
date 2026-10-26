terraform {
  required_version = ">= 1.11, < 2.0"

  backend "s3" {
    bucket       = "acme-tfstate"
    key          = "core/terraform.tfstate"
    region       = "eu-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
