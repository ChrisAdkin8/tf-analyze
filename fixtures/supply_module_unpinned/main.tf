# Expected findings:
#  - SEC-SUPPLY-001 HIGH — git source pinned to a branch, not a SHA or tag

module "vpc" {
  source = "github.com/terraform-aws-modules/terraform-aws-vpc?ref=main"
  name   = "primary"
}

module "iam" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-iam.git?ref=master"
  region = "us-east-1"
}

# Pinned to a commit SHA and to a release tag — OK, no finding
module "sha" {
  source = "git::https://github.com/acme/net.git?ref=4f3d8b6c9a2e1f70d8b4c6e2a1f93d7c0b5e8f44"
}

module "tag" {
  source = "git::https://github.com/acme/net.git?ref=v1.2.3"
}
