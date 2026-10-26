module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.13.0"

  name = "core"
  cidr = "10.0.0.0/16"
}
