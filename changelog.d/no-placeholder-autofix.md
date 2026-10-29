## `--apply-fixes` doesn't paste example tag values

- **Tag and label rules**: `OPS-AWS-TAGS-001`, `OPS-AZURE-TAGS-001` and
  `OPS-GCP-LABELS-001` had `fix_disruption: none` and a `fix_hcl` of
  made-up values (`Owner = "platform-team"`, `Environment = "prod"`), so
  `--apply-fixes` and the auto-remediation bot pasted them into real
  resources, which also made those resources look like production to other
  rules. A new catalogue field, `fix_hcl_example: true`, marks a snippet
  whose values a person has to choose: it is still shown in reports and PR
  comments, `--apply-fixes` skips it, and the bot's PR body doesn't count
  it. JSON findings carry `fix_hcl_example: true` for those rules.
