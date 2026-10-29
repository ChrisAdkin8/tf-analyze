## Dead rule patterns fire, and the catalogue rejects patterns that can't

- **`SEC-K8S-PSA-001` helm checks never fired**: its three `helm_set_value`
  patterns (`securityContext.runAsNonRoot`, `readOnlyRootFilesystem`,
  `capabilities.drop`) had `expected:` and no `regex:`, and the handler
  skips a pattern without `regex:`. A `helm_release` that sets
  `runAsNonRoot` or `readOnlyRootFilesystem` to `false`, or a
  `capabilities.drop` list without `ALL`, is now reported. Only a
  literal value is judged: `helm_set_value` now skips an expression
  (`var.x`, `lookup(var.m, "k")`, `"${...}"`) and a missing value, on the
  parse-tree and the regex fallback path alike. The fallback also reads
  one-line helm provider v3 items (`{ name = "a", value = "b" }`), whose
  name it used to run into the value.
- **The catalogue loader catches dead patterns**: a pattern missing a key
  its kind needs (`helm_set_value` without `regex`, `resource_arg` without
  `regex`/`not_regex`, `hcl_attr` without `not_equal`, `resource_absent`
  without `resource`, …), an unknown `iam_*_policy_analysis` `check:`,
  or an unknown `graph_check` `function:` is dropped with a `WARN` naming
  the rule and pattern; the rest of the rule still loads. A rule with no
  usable pattern left is skipped with a `WARN`. Under `--strict-catalog`
  each is an `ERROR` and exit 2, for custom rules (`.tf-analyze-rules/`)
  as well. PSA-001 was the only shipped entry affected.
- **GCP public access through `_iam_binding`**: `SEC-GCP-IAM-002` now
  covers `google_project_iam_binding`, and `SEC-GCP-CLOUDRUN-002` covers
  `google_cloud_run_service_iam_binding` and
  `google_cloud_run_v2_service_iam_binding`, when `members` includes
  `allUsers` or `allAuthenticatedUsers`. They read only the singular
  `member` of the `_iam_member` resources before. A public
  `google_bigquery_dataset_iam_member` is now reported once, by
  `SEC-GCP-BIGQUERY-001` (which already covers the dataset's access
  block, member and binding forms), not also by `SEC-GCP-IAM-002`.
- **`NotAction` / `NotResource` in JSON policies**: `SEC-AWS-IAM-POLICY-006`
  read `aws_iam_policy_document` only. It now also reports an Allow
  statement with `NotAction` or `NotResource` in a `policy` on
  `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`,
  `aws_iam_group_policy` or an `aws_iam_role` `inline_policy`.
- **`Action: "*"` with `NotResource` is the admin shape**: every action on
  every resource bar a few is AdministratorAccess in all but name. It is
  now `SEC-AWS-IAM-JSON-003` / `SEC-AWS-IAM-POLICY-005` (CRITICAL), not a
  HIGH wildcard action (`SEC-AWS-IAM-JSON-001` / `-POLICY-001`), and
  `SEC-AWS-IAM-POLICY-006` doesn't report it again.
- The terragoat corpus gains a public Cloud Run invoker binding (GCP) and
  a `NotAction` JSON policy (AWS); the snapshot moves to gcp 114, aws 124,
  total 364.
