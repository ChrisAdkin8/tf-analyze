## variable, output, provider and version rules ignore comments

Findings change: commented-out code no longer hides or causes a
finding, and a few missed problems are now caught.

- **Unused variables / outputs** (`ROB-UNUSED-001` / `-002`): a
  `var.x` or `module.m.out` in a comment counted as a use. A
  variable's mention of itself in its own `validation` block also
  counted, so no validated variable was ever reported unused.
  Heredoc text (`${var.x}` in `user_data`) still counts.
- **Provider aliases** (`ROB-PROVIDER-ALIAS-002`): `"aws.west"` in a
  string counted as using the alias; only code references count now.
  `ROB-PROVIDER-ALIAS-001` skips commented-out `providers` entries.
- **Backends** (`ROB-BACKEND-001`): a `backend` block inside `/* */`
  counted as a second backend.
- **Versions**: `ROB-VERSION-003` skips commented-out
  `required_providers` entries and no longer takes a commented-out
  `version` as set; `ROB-VERSION-002` no longer takes a commented-out
  `required_version` as set; `ROB-VERSION-001` reads every `.tf` file,
  not only `versions.tf`. Its own `fix_hcl` and the `clean_baseline`
  fixture pinned `>= 1.5.0`, which the rule calls too old; both now say
  `>= 1.6.0`.
