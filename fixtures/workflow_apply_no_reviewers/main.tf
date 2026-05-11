# Workflow runs `terraform apply` without an `environment:` block,
# so SEC-CICD-001 fires on the YAML file. The .tf file here is
# inert; the rule is workflow-scoped.

resource "null_resource" "placeholder" {}
