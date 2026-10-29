## Hardcoded secrets in `provider`, `locals` and module blocks are reported

- **Entropy rule**: `SEC-SECRETS-ENTROPY-001` only checked `resource`
  blocks, so a random-looking key in a `provider` block (`secret_key`,
  `token`), a `locals` value, a module input or a data source was never
  flagged. It now checks all five block kinds, and quoted map keys
  (`"token" = "..."`).
- **Name rule**: `SEC-SECRETS-001` matched names ending in `password`,
  `secret` or `api_key`. It now also matches `secret_key`, `private_key`
  and any name ending in `token` (`token`, `access_token`,
  `github_token`), and quoted map keys (`"password" = "..."`), in `.tf`,
  `.tfvars` and `.tfvars.json`. So the AWS provider's
  `secret_key = "..."`, a GitHub provider's `token = "ghp_..."` and a
  `locals` map password are reported. References (`var.*`, `"${...}"`,
  data sources) still aren't.
