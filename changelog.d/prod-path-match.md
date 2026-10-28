## Production means the word, not the letters "prod"

Findings change: fewer false alarms from `OPS-ENV-001` and the
`INT-INTENT-003` / `-004` intent-gap rules.

- **Paths**: `OPS-ENV-001` treated any path containing `prod` as
  production, so `nonprod/`, `preprod/`, `products/` and even a parent
  folder above the scan target counted. A folder or file name under the
  target now counts when one of its words (split on `-` `_` `.`) is
  `prod`, `production` or `prd`, and none is `pre` / `non` / `not`
  (`envs/prod-eu/` yes, `pre-prod/` no).
- **Labels**: `environment = "prod…"` was matched in raw text, so a
  commented-out label or `"prodigy"` counted. `OPS-ENV-001` and the
  intent-gap rules now share one check: an `environment` or `env` key set
  to a production value, comments ignored. A commented-out
  `deletion_protection = false` or `force_destroy = true` no longer counts
  either.
