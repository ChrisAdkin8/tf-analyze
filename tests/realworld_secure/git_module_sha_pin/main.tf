module "network" {
  source = "git::https://github.com/acme/terraform-network.git?ref=4f3d8b6c9a2e1f70d8b4c6e2a1f93d7c0b5e8f44"

  name = "core"
}
