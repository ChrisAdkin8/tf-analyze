# Workflow uses `permissions: write-all` — SEC-CICD-002 fires.
# The `environment:` block keeps SEC-CICD-001 quiet for this fixture
# so the test isolates the write-all check.

resource "null_resource" "placeholder" {}
