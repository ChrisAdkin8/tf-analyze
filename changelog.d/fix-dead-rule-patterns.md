## Dead rule patterns fire, and the catalogue rejects patterns that can't

- **`SEC-K8S-PSA-001` helm checks never fired**: its three `helm_set_value`
  patterns (`securityContext.runAsNonRoot`, `readOnlyRootFilesystem`,
  `capabilities.drop`) had `expected:` and no `regex:`, and the handler
  skips a pattern without `regex:`. A `helm_release` that sets
  `runAsNonRoot` or `readOnlyRootFilesystem` to `false`, or a
  `capabilities.drop` list without `ALL`, is now reported.
- **The catalogue loader rejects dead patterns**: a pattern missing a key
  its kind needs (`helm_set_value` without `regex`, `resource_arg` without
  `regex`/`not_regex`, `grep` without `regex`, …) is now an `ERROR`, and
  exit 2 under `--strict-catalog`, instead of a rule that silently never
  fires. So is an `iam_policy_analysis` / `iam_json_policy_analysis`
  `check:` the engine doesn't know. PSA-001 was the only shipped entry
  affected. Custom rules (`.tf-analyze-rules/`) are checked the same way.
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
