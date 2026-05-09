# Clean fixture: only one module exists, it IS referenced — no orphan.
module "used" {
  source = "../../modules/used"
  name   = "demo"
}
