# Expected findings:
#  - SEC-SUPPLY-001 HIGH — git source without ref= pin

module "vpc" {
  source = "github.com/terraform-aws-modules/terraform-aws-vpc"
  name   = "primary"
}

module "iam" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-iam.git"
  region = "us-east-1"
}
