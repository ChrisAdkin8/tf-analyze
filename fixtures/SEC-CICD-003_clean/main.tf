# `terraform apply -auto-approve` IS used, but the apply job declares
# a protected `environment: production` — SEC-CICD-003 must NOT fire.

resource "null_resource" "placeholder" {}
