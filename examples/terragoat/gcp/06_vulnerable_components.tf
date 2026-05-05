# OWASP A06:2021 — Vulnerable and Outdated Components
# Cloud: GCP
#
# Four shapes of "outdated component" in Terraform:
#
#   1. Module sources without a `version` constraint — you ship
#      whatever HEAD looks like the day you `terraform init`. Module
#      authors can (and do) make breaking changes.
#   2. Provider constraints with no upper bound (`~> 5.0` is a soft
#      upper bound; `>= 5.0` is no upper bound). Major version bumps
#      land silently.
#   3. `required_version` not set, or set to a lax range. Different
#      operators run different TF versions; behaviour diverges.
#   4. Cloud-managed runtimes pinned to deprecated versions
#      (`POSTGRES_9_6`, `nodejs10`).
#
# Real-world impact:
#   - "Worked on Friday, broken on Monday" — a module repo retags
#     `latest` and nobody can apply.
#   - A provider rev silently changes default values; resources are
#     replaced on the next plan.
#   - Cloud functions on EOL runtimes lose security patches and stop
#     receiving CVE fixes from Google.
#
# Expected tf-analyze findings:
#   - MOD-PIN-001        MEDIUM   Registry module source missing version
#   - SEC-PROVIDER-001   MEDIUM   Provider constraint missing upper bound
#   - ROB-VERSION-001    LOW      required_version older than recommended floor
#   - STK-DEPRECATION-001 / 002   Deprecated provider attribute / data source
#
# Fix summary: pin every module to an exact version (or a
# `~> X.Y.Z` if you want minor patches). Set `required_version` and
# `required_providers.<name>.version` with both lower and upper
# bounds. Re-run `terraform init -upgrade` deliberately, never
# accidentally.

module "unpinned_network" {
  source = "terraform-google-modules/network/google"
  # version intentionally omitted — pulls HEAD on every init.

  project_id   = "demo-project"
  network_name = "demo-vpc"
  subnets      = []
}

# Cloud SQL pinned to a deprecated version. The `database_version`
# argument accepts EOL strings until they're formally removed by the
# provider; meanwhile no security backports are applied upstream.
resource "google_sql_database_instance" "legacy" {
  name             = "demo-legacy"
  region           = "us-central1"
  database_version = "POSTGRES_9_6"

  settings {
    tier = "db-f1-micro"
  }

  deletion_protection = true
}
