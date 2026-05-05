# Expected findings:
#  - MOD-PIN-001 HIGH — registry module without `version` constraint
#  - MOD-PIN-001 HIGH — git module source without `?ref=` pin
#  - MOD-PIN-001 HIGH — github.com source without `?ref=` pin

terraform {
  required_version = "~> 1.10"
}

# Registry module — no version pin (finding)
module "network" {
  source     = "terraform-google-modules/network/google"
  project_id = "test-project"
  network_name = "vpc"
  subnets    = []
}

# Git module — no ?ref= pin (finding)
module "vault" {
  source = "git::https://github.com/hashicorp/terraform-vault-aws.git"
}

# GitHub shorthand — no ?ref= pin (finding)
module "consul" {
  source = "github.com/hashicorp/terraform-consul-aws"
}

# Pinned git module — OK, no finding
module "pinned" {
  source = "git::https://github.com/hashicorp/example.git?ref=v1.2.3"
}

# Local module — OK, no finding
module "local" {
  source = "./modules/local"
}
