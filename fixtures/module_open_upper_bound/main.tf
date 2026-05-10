# Expected findings:
#  - MOD-SUPPLY-004 MEDIUM — version = ">= 5.40" has no upper bound

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = ">= 5.40"
  name    = "primary"
}
