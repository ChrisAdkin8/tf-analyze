## Stop saying things are fine when they aren't: plan-only scans, verify-fixed, apply-fixes

- **Plan-only scans find more, and say what they skipped**: a scan with
  `--plan-json` and no source files (every Run Task) ran only five pattern
  kinds and skipped the rest without a word. A plan with an admin IAM
  policy, SSH open to the world and a public bucket policy scored 100 (A),
  exited 0, and the Run Task said "passed". The plan's values are now
  rendered as HCL for the rules that judge resolved values
  (`iam_json_policy_analysis`, `iam_policy_analysis`, `firewall_open_port`,
  `ip_range_span`, `helm_set_value`, `resource_has_block`,
  `deprecated_datasource`, the ECS `container_definitions` rules), and
  `resource_absent` and `resource_missing_companion` run on the plan. That
  plan now exits 1. Unevaluated rules fall from 123 to 72 of 352, and from
  34 to 15 CRITICAL / HIGH. `--state-json` with no source works the same way.
- **Unknown values are named**: a value unknown until apply isn't in the
  plan, so a rule reading it found nothing. `after_unknown` is now read: a
  resource with an unknown value in an argument a rule reads is listed in
  `summary.coverage.unknown_values`, in the `PARTIAL SCAN` line and in the
  Run Task message. An `aws_iam_policy_document` read at apply keeps its
  known parts and is judged on them; `jsonencode({...})` with one unknown
  value is one unknown string, and the plan holds none of it.
- **Plans that can't be trusted exit 2**: an unknown `format_version` major,
  or `resource_changes` creating what `planned_values` doesn't have, read as
  no resources: score 100 (A), exit 0.
- **Large plans stay fast**: the rendered pass reads only arguments a rule
  reads, skips resources that can't fire, and no longer slows down on
  same-named instances or on companions.
- **A plan-only score says it is partial**: `summary.coverage` counts what
  did not run, stderr gets a WARN, and text, HTML, `pr-summary`, SARIF,
  compliance, MITRE, OSCAL and PDF output carry a `PARTIAL SCAN` line. A
  compliance control with a rule that didn't run is `NOT-EVALUATED`, not
  `PASS`. The Run Task still returns `passed`
  when nothing breaches the threshold (there is no third status, and every
  plan has rules that can't run), but the message says what that covers.
  See `docs/run-task.md`. It now returns `failed` when a rule check ran out
  of time or the engine's gate failed: it used to read findings alone.
- **`--mode verify-fixed` can't call an unchecked finding fixed**: it
  re-probed `.tf` files only, so a secret in `prod.auto.tfvars` came out
  RESOLVED with nothing changed, and exit 0. It now reads what the scan
  reads (tfvars, workflow YAML), and RESOLVED needs evidence. A finding
  from a plan or state, in a file outside the corpus, or of a rule with no
  offline check or that ran out of time, is the new UNVERIFIABLE state.
  `--fail-on` gates on UNVERIFIABLE, AMBIGUOUS and BROKEN-SYMLINK too.
  Text and markdown reports also lost every row for a non-`.tf` file, a
  path with a space or `+`, a `🔥 KEV` line and a repository-level `.:0` row;
  those are read, and a row that looks like a finding but can't be read
  fails `--fail-on`.
- **A report it can't read is an error**: a prior report with no rows that
  doesn't say it found nothing (`--format pr-summary`, an empty file) passed
  on a repository full of CRITICALs. It now exits 2. A `verify-fixed` report
  is no longer picked up as the prior report, which turned a CI retry green.
- **`--apply-fixes` no longer breaks valid Terraform**: it pasted snippets
  such as `kms_key_id = aws_kms_key.logs.arn` into modules with no such key,
  so `terraform validate` failed where it had passed, and the run reported
  success. A fix that references a resource, data source, variable, local
  or module the file's own module doesn't declare, or that holds a
  placeholder (`projects/example/...`, a documentation IP), is now left out.
  So is a fix that belongs in a nested block (`SEC-AWS-ATHENA-001` pasted
  `encryption_option` at the top of the resource: "Unsupported argument").
  So is one that names a `count` / `for_each` resource with no index, or
  uses `each.` / `count.` in a block without them. Dry runs do the same.
  Every fix left undone gets a `# apply-fixes: manual:` line with its
  reason, and the "applied" count, and the file count, are what really
  changed; each candidate is applied, covered by another rule's fix, or listed.
- **One-click fixes too**: such a finding now carries `fix_manual_reason`,
  from the same decision the patcher makes. `--mode pr-review` shows the fix
  as advice, and the GitHub Action, its template and the editor quick fix
  don't offer it.
- **Bot PR body**: it read only "would apply", so a real run reported every
  candidate as applied. It now reads the real count and adds a **Needs manual
  work** section.
- **Catalogue**: 14 rules whose patch needs another resource or a real value
  move from `fix_disruption: none` to `plan_required`, so the bot leaves them
  (`SEC-AWS-CWL-001`, `SEC-AWS-ALB-001`, `SEC-AWS-ATHENA-001`, `SEC-AWS-SECRETSMANAGER-001`,
  `SEC-GCP-COMPUTE-SA-001`, `SEC-GCP-SECRET-001`, `SEC-AZURE-AKS-OMS-001`,
  `SEC-AZURE-SQL-001`, `SEC-AZURE-SQL-002`, `SEC-AZURE-WEBAPP-001`,
  `SEC-GCP-IAM-002`, `ROB-GCP-DISK-SNAP-001`, `STK-AZURE-FUNCTION-002`,
  `STK-GCP-PUBSUB-DLQ-001`). 8 rules become `fix_hcl_example: true`:
  `SEC-AZURE-WEBAPP-001`, `SEC-AZURE-SQL-001`, `SEC-GCP-BQ-CMEK-001`,
  `SEC-GCP-GKE-DBENC-001`, `SEC-GCP-SPANNER-001`, `SEC-GCP-SECRET-001`,
  `SEC-K8S-HELM-003`, `STK-AZURE-AKS-VERSION-001`.
