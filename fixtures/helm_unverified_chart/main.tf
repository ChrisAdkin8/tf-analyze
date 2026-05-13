resource "helm_release" "unverified" {
  name       = "app"
  repository = "https://charts.example.io"
  chart      = "app"
  verify     = false
  # No `version` pinned — chart resolves to whatever "latest" the
  # repository serves at apply-time. Two ways this rule fires on
  # one resource: missing `version` AND explicit `verify = false`.
}
