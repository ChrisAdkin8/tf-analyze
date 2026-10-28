## lifecycle and block rules ignore comments

Findings change: commented-out blocks no longer satisfy a rule, and
two missed forms are now caught.

- **`ROB-CHECK-001`**: an `assert {}` inside `/* */` counted as an
  assertion.
- **`ROB-VALIDATION-001`**: a `validation {` inside `/* */` or a heredoc
  (`description = <<EOT`) counted as a validation block. Only a
  top-level block counts now.
- **`ROB-DRIFT-003`**: a comment inside `ignore_changes = [ ... ]` was
  split on its commas and counted as attributes.
- **`ROB-DRIFT-002`**: `terraform fmt` writes `ignore_changes = [\n tags,\n]`
  with a trailing comma, which the regex missed (same for `["*",]`).
- **`ROB-*-LIFECYCLE-001`**: `lifecycle { prevent_destroy = false }`
  passed the rule, though it protects nothing. Each type now also has
  an `hcl_attr` pattern that fires when it is not `true`.
