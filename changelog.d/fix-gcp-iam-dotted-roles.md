## `SEC-GCP-IAM-001` catches dotted admin roles

- **Missed roles**: the rule's regex was double-quoted, so its `\\.`
  looked for a literal backslash and every dotted role never matched:
  `roles/storage.admin`, `roles/compute.admin`, `roles/iam.securityAdmin`
  and the other `*.admin` roles. Only `roles/owner`, `roles/editor` and
  `roles/admin` were reported. The regexes are now single-quoted.
- **Load-time check**: the catalogue loader now rejects a pattern regex
  with a literal backslash before a regex escape (`\\.`, `\\s`, ...), so
  this can't ship again. `--strict-catalog` fails on it, and a custom rule
  with it is skipped with an error.
