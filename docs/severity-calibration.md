# Severity calibration log

This document records explicit calibration decisions for `default_urgency`
in `catalog/*.yaml`. The intent is that severity is *defensible*, not
arbitrary — when a rule's urgency is changed, the rationale lives here so
future maintainers can see why.

## Methodology

A rule's `default_urgency` is set by considering:

1. **Worst-case consequence** under the catalogue's `blast_radius`
   classification. A misconfiguration that loses one row of test data is
   not a CRITICAL even if it touches sensitive data; the same
   misconfiguration on a production credential store is.
2. **Exploitability**. Rules that detect a *direct* path to compromise
   (no chained prerequisites, no privileged context required) rank
   higher than rules that need an attacker to already hold a foothold.
3. **Detection-evasion impact**. Rules that disable observability
   (CloudTrail, VPC Flow Logs, GuardDuty) rank one tier above the
   median because they make every other rule less detectable in
   production.
4. **Industry baselines**. Where checkov / tfsec / Prowler ship a
   similar rule, we calibrate to the median; where we diverge, the
   reason is recorded below.

## Tiers

| Urgency  | Meaning                                                                 |
|----------|-------------------------------------------------------------------------|
| CRITICAL | Immediate-blast: data exposure, privilege escalation, or audit blackout |
| HIGH     | Direct security boundary breach with realistic exploit path             |
| MEDIUM   | Defense-in-depth gap; exploitation needs a chained vulnerability        |
| LOW      | Style / hygiene / advisory                                              |
| INFO     | Information-only; never CI-blocking                                     |

## Round-23 calibration adjustments

| Rule ID                  | From | To       | Rationale                                                                                                                                                              |
|--------------------------|------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SEC-AWS-CLOUDTRAIL-001   | HIGH | CRITICAL | Single-region CloudTrail = audit blackout for every other region. Realistic attacker move during incident response evasion. CIS Benchmark 3.1 also treats as critical. |
| SEC-AWS-IAM-POLICY-006   | HIGH | MEDIUM   | `not_actions` / `not_resources` is a code-smell, not a guaranteed exposure. Engine already excludes `Effect = "Deny"`, so positives are advisory.                      |

## 2026-10-28 calibration adjustments

Goal: a minimal, secure module passes `--fail-on HIGH`. Before, a
private, versioned S3 bucket with a full public access block still failed
on two HIGHs (`ROB-AWS-LIFECYCLE-001`, `SEC-AWS-S3-001`), and 55% of
active rules were HIGH or CRITICAL. Rules in the `robustness` section are
now at most MEDIUM (`tests/test_severity_calibration.py` keeps it so):
they cover data loss and plan/apply breakage, not a security boundary.
Free-text `is_production_environment` escalations (judgement-pass
guidance; the engine ignores them) now go one tier up, not to CRITICAL.

| Rule ID | From | To | Rationale |
|---|---|---|---|
| ROB-AWS-LIFECYCLE-001, ROB-AZURE-LIFECYCLE-001, ROB-GCP-LIFECYCLE-001 | HIGH | LOW | `prevent_destroy` is a Terraform workflow guard. The real risk, deleting a stateful resource, is covered by the deletion-protection rules. At HIGH it put a HIGH on every bucket, database and table. |
| SEC-AWS-S3-001 | HIGH | LOW | Since January 2023 S3 encrypts every new object with SSE-S3, so a bucket without an encryption resource is encrypted at rest. What is left is the SSE-S3 vs KMS choice: advisory. |
| SEC-AWS-S3-PUBLIC-BLOCK-001 | HIGH | MEDIUM | Overturns the standing decision below. Since April 2023 new buckets have Block Public Access on and ACLs off by default, so a missing block resource is a defence-in-depth gap, not an exposure. An actually public ACL or grant is `SEC-AWS-S3-PUBLIC-001` (HIGH). |
| ROB-AWS-RDS-001, ROB-AWS-RDS-002, ROB-AWS-RDS-003, ROB-AWS-DDB-001, STK-GCP-CLOUDSQL-001, STK-GCP-CLOUDSQL-003 | HIGH | MEDIUM | Backups, final snapshot and deletion protection: data loss after a mistake or a compromise, not a way in. |
| ROB-AWS-LIFECYCLE-002, ROB-GCP-LIFECYCLE-002 | HIGH | MEDIUM | `force_destroy` lets `terraform destroy` empty a bucket: data loss, not exposure. |
| ROB-COUNTNAME-001, ROB-COUNTREF-002, ROB-FOREACH-002, ROB-DRIFT-001, ROB-PROVIDER-ALIAS-001, ROB-VERSION-003, ROB-AWS-BACKEND-001 | HIGH | MEDIUM | Plan/apply correctness (re-keying, drift hidden by `ignore_changes = all`, an undeclared alias, unpinned providers, no state lock): real outages, no security boundary. |

Not yet swept: the 103 HIGH `security` rules and the 43 HIGH `stack`
rules (end-of-life runtimes, cluster hardening). They need a rule-by-rule
look against the tiers above.

## Standing decisions (no change, but documented)

| Rule ID                       | Urgency  | Why                                                                                            |
|-------------------------------|----------|------------------------------------------------------------------------------------------------|
| SEC-AWS-IAM-POLICY-005        | CRITICAL | `actions=["*"]` AND `resources=["*"]` = canonical AdministratorAccess shape; one statement, full account compromise. |
| SEC-AWS-IAM-POLICY-004        | CRITICAL | `principals.identifiers=["*"]` makes whatever resource the policy attaches to public.          |
| SEC-AWS-IAM-POLICY-002        | CRITICAL | `iam:*` action grants self-mutating IAM (privesc class).                                       |
| SEC-AWS-IAM-POLICY-001        | HIGH     | `actions=["*"]` alone is bad but scoped to `resources` set. Promote when paired with -005.     |
| SEC-AWS-IAM-POLICY-003        | HIGH     | Symmetric: `resources=["*"]` alone is bad but scoped to `actions` set.                          |
| ROB-VERSION-002               | LOW      | Hygiene — submodule version pinning. Doesn't change runtime behaviour.                         |

## Calibration cadence

Spot-check 5 rules per major round; full sweep every 3 rounds. Track
positive/negative fixture pass rates per urgency tier to detect rules
that are mis-tiered (e.g. CRITICAL with high false-positive rate).
