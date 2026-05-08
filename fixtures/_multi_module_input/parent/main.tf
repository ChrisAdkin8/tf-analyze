# Parent module overrides the child's `encrypted` default.
# Round 24 added module-input flow-through; this fixture is the
# multi-file regression test for that path.

module "child" {
  source    = "../modules/child"
  encrypted = false   # Caller injects false → child's resource fires SEC-AWS-EBS-001.
}
