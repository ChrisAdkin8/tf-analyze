# Workflow runs `terraform apply` inside a protected `environment:`
# block, so SEC-CICD-001 must NOT fire.

resource "null_resource" "placeholder" {}
