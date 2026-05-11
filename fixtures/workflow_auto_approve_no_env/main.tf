# `terraform apply -auto-approve` without an `environment:` block
# fires SEC-CICD-003 (CRITICAL) and SEC-CICD-001 (HIGH).

resource "null_resource" "placeholder" {}
