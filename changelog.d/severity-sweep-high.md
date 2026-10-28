## Most security and stack rules no longer block `--fail-on HIGH`

Severity change only: no finding appears or disappears. All 143 active
HIGH rules in `security` and `stack` were reviewed; 109 move down a tier
and 34 stay HIGH. Each reason is in `docs/severity-calibration.md`.
Active rules at HIGH or CRITICAL: 175 of 352 (50%) → 66 (19%).

- **MEDIUM** (107): encryption in transit and TLS versions, encryption at
  rest, WAF, network policies, private endpoints for services that still
  need credentials, flow logs and per-resource logs, per-resource threat
  detection, key rotation, default service accounts, supply-chain
  hygiene, `sensitive` markers, and end-of-life runtimes and versions.
- **LOW** (2): `SEC-AWS-SQS-001` (new queues get SQS-managed encryption by
  default) and `STK-GCP-BIGQUERY-001` (BigQuery encrypts every dataset;
  CMEK is a key choice).
- `SEC-AWS-GUARDDUTY-001` and `SEC-AZURE-DEFENDER-001` fired on any repo
  that does not declare them, though both are usually enabled org-wide;
  they are MEDIUM. An explicit Defender `tier = "Free"` is still HIGH.
- Still HIGH: wildcard IAM, world-open ports and public data stores,
  disabled auth, secrets in code or state, IMDSv1, privileged
  containers, and the account audit trail.
- Data-store at-rest encryption rules escalate back to HIGH in
  production (judgement pass).
- A plain AWS, Azure or GCP workload module (queue, function, VPC; storage
  account and Key Vault; private bucket and Cloud Run) now passes
  `--fail-on HIGH`; before, each failed on two or three HIGHs.
