# Fixture for MOD-STALE-001.
# This fixture intentionally uses a registry-style source with an old pinned version.
# The actual staleness comparison requires a live registry query (--check-registry)
# and therefore cannot be asserted in the offline self-test. This fixture is
# documented here for manual verification with --check-registry. (offline self-test skips live network checks)

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "= 2.0.0"

  name = "my-vpc"
  cidr = "10.0.0.0/16"
}
