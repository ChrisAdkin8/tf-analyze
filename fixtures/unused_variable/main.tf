module "child" {
  source = "./child"
  name   = var.project_id
}

# bucket_url is consumed — no finding
output "url" {
  value = module.child.bucket_url
}

# orphan_output is NOT consumed — ROB-UNUSED-002 should fire
