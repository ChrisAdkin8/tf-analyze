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

## Standing decisions (no change, but documented)

| Rule ID                       | Urgency  | Why                                                                                            |
|-------------------------------|----------|------------------------------------------------------------------------------------------------|
| SEC-AWS-IAM-POLICY-005        | CRITICAL | `actions=["*"]` AND `resources=["*"]` = canonical AdministratorAccess shape; one statement, full account compromise. |
| SEC-AWS-IAM-POLICY-004        | CRITICAL | `principals.identifiers=["*"]` makes whatever resource the policy attaches to public.          |
| SEC-AWS-IAM-POLICY-002        | CRITICAL | `iam:*` action grants self-mutating IAM (privesc class).                                       |
| SEC-AWS-IAM-POLICY-001        | HIGH     | `actions=["*"]` alone is bad but scoped to `resources` set. Promote when paired with -005.     |
| SEC-AWS-IAM-POLICY-003        | HIGH     | Symmetric: `resources=["*"]` alone is bad but scoped to `actions` set.                          |
| SEC-AWS-S3-PUBLIC-BLOCK-001   | HIGH     | Consequence depends on bucket contents (could be empty, intended-public, or PII). Industry baseline is HIGH. |
| ROB-VERSION-002               | LOW      | Hygiene — submodule version pinning. Doesn't change runtime behaviour.                         |

## Calibration cadence

Spot-check 5 rules per major round; full sweep every 3 rounds. Track
positive/negative fixture pass rates per urgency tier to detect rules
that are mis-tiered (e.g. CRITICAL with high false-positive rate).
