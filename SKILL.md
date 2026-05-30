---
name: tf-analyze
description: Analyze Terraform code (GCP-first; AWS/Azure secondary) for best practices, style, robustness, DRY/code reuse, security posture, simplicity, operational readiness, and CI/CD maturity. Generates a structured report with stable catalogue-backed finding IDs, urgency, blast radius, CIS benchmark mapping, deterministic risk score, and delta tracking against previous runs. Use when you want a comprehensive audit, before a major refactor, or to verify fixes from a prior report.
argument-hint: "[path:tf/modules/foo] [focus:security|dry|style|robustness|simplicity|ops|cicd|cross-module|stack|compliance|all] [format:markdown|json|sarif|html|compliance] [mode:static|diff|plan|verify-fixed|self-test] [diff-base:main] [compliance-framework:cis|pci_dss|soc2|all] [check-registry] [apply-fixes:dry-run|apply] [cache]"
allowed-tools: Bash, Read, Glob, Grep, Write, Agent
model: claude-opus-4-6
---

# Terraform Code Analyzer

Perform a comprehensive analysis of Terraform code in the current repository and generate a structured report with prioritized, catalogue-backed findings.

## Quickstart

```bash
# Default scan: all focus areas, static mode, markdown report.
/tf-analyze

# Scope to a single module + security only:
/tf-analyze path:tf/modules/iam focus:security

# PR review: only files changed since main, fail on HIGH+, SARIF for CI:
/tf-analyze mode:diff format:sarif diff-base:main

# Verify a prior report's findings are resolved without re-scanning:
/tf-analyze mode:verify-fixed
```

`detect.py` (the deterministic detection pass invoked by Steps 2–10) also has standalone meta-commands that don't require a target:

```bash
scripts/detect.py --list-rules                # all catalogue IDs grouped by domain
scripts/detect.py --list-rules --focus security
scripts/detect.py --explain SEC-GCP-IAM-001       # full entry for one rule
scripts/detect.py --new-rule SEC-FOO-007      # scaffold catalog YAML + fixture
scripts/stub-status.py --age 90d              # find stubs older than 90 days
```

## Table of Contents

1. [Arguments](#arguments)
2. [Execution Modes](#execution-modes)
3. [Cloud scope](#cloud-scope)
4. [Architecture: detection vs judgement](#architecture-detection-vs-judgement)
5. [Urgency Levels](#urgency-levels)
6. [Blast Radius](#blast-radius)
7. [Suppression](#suppression)
8. [CI Integration](#ci-integration) — SARIF, HTML, `--compare`, `--fail-on`, optional python-hcl2
9. **Step 0** — Pre-Analysis: credential scan + hygiene
10. **Step 1** — Discovery (file enumeration, dependency graph, sentinel tempdir)
11. **Step 2** — Security Posture
12. **Step 3** — DRY and Code Reuse
13. **Step 4** — Style and Conventions
14. **Step 5** — Robustness
15. **Step 6** — Simplicity
16. **Step 7** — Operational Readiness
17. **Step 8** — CI/CD and Testing Maturity
18. **Step 9** — Cross-Module Contracts
19. **Step 10** — Stack-Specific (Vault, Consul, GKE, Helm)
20. **Step 11** — CLAUDE.md Convention Verification
21. **Step 12** — Cost Estimation (delegates to the `tf-cost` skill when available)
22. **Step 13** — Plan-Time Analysis (mode:plan only)
23. **Step 14** — Recommendation Verification (sentinel tempdir)
24. **Step 15** — Verify-Fixed Mode
25. **Step 16** — Report Generation
26. **Step 17** — Summary Output
27. **Step 18** — Self-Test Mode
28. [Appendix A](#appendix-a-iam-resource-level-binding-compatibility-matrix) — IAM compatibility matrix
29. [Appendix B](#appendix-b-cost-classification-heuristics) — cost classification heuristics

## Arguments

$ARGUMENTS

Parse from `$ARGUMENTS`:
- `path:PATH` — scope analysis to a specific directory (default: scan entire repo for `.tf` files)
- `focus:AREA` — limit to one area: `security` (Step 2), `dry` (Step 3), `style` (Step 4), `robustness` (Step 5), `simplicity` (Step 6), `ops` (Step 7), `cicd` (Step 8), `cross-module` (Step 9), `stack` (Step 10), `compliance` (Step 11 CLAUDE.md verification), or `all` (default: `all`). When a single focus is selected, only that step's analysis section appears in the report; Steps 0 (credential scan), 12 (cost), and 16/17 (report generation) always run.
- `format:FORMAT` — output format: `markdown` (default), `json`, `sarif` (SARIF v2.1.0 for CI annotation — GitHub Actions, Azure DevOps, etc.), or `html` (self-contained HTML report for human review)
- `mode:MODE` — see **Execution Modes** below
- `diff-base:REF` — git ref to diff against when using `mode:diff` (default: auto-detect `main` or `master`)

If no arguments are provided, analyze all Terraform code in the repo across all focus areas in static mode and output markdown.

---

## Execution Modes

The skill has five execution modes. Pick the right one before starting — they have very different blast radii on context, runtime, and required credentials.

| Mode | Cost | Credentials? | Output | When to use |
|---|---|---|---|---|
| **`static`** (default) | ~5 min | No | Full report | First-time audit, post-refactor sanity check, anything where you want comprehensive coverage |
| **`diff`** | ~1 min | No | Scoped report (changed files only) | PR review, pre-merge check, incremental CI gating. Only scans files changed vs the base branch. |
| **`plan`** | ~15 min | Yes (read state, run plan) | Full report + plan-time findings | When you suspect drift, when you want destroy-recreate detection, when you need real `for_each` expansion counts |
| **`verify-fixed`** | ~1 min | No | Verification report only | Between full runs, to confirm a previous report's findings are actually resolved without re-scanning |
| **`self-test`** | ~2 min | No | Pass/fail per fixture | After editing the skill or the catalogue. Asserts that fixtures under `fixtures/` produce exactly their expected catalogue IDs. **Run before committing skill changes.** |

### Mode-specific procedures

- **`static`** — runs Steps 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 14 → 16 → 17, skipping Step 13 (plan analysis), Step 15 (verify mode), and Step 18 (self-test). The deterministic detection pass via `scripts/detect.py` runs **inside** Steps 2–10 — it is a tool, not a numbered step — and supplies the catalogue-anchored finding IDs that the report references. Step 11 (CLAUDE.md Convention Verification) is the named LLM-judgement step.
- **`diff`** — same steps as `static`, but `scripts/detect.py` is invoked with `--diff-base <base-branch>`. Only `.tf` files changed between the base branch and HEAD are scanned per-file; corpus-level checks (unused variables, absent resources) still run against all files but filter results to changed files. The report title includes "(diff vs `<base>`)". Use `diff-base:REF` argument to override the default base (auto-detected as `main` or `master`).
- **`plan`** — runs every step `static` runs **plus** Step 13 (plan analysis). Sequence: 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 16 → 17. Step 13 requires `terraform init && plan` against a real backend, so credentials must be available. Steps 11 and 12 always run (they consume static-pass output, not plan output).
- **`verify-fixed`** — skips Steps 1–14 entirely. Runs only Step 15 (verification mode), reading the most recent prior report and re-probing each finding's location.
- **`self-test`** — runs Step 18 (self-test loop) only. Walks `fixtures/` and the `catalog/`, asserts each fixture produces its declared IDs and no others.

---

## Cloud scope

The skill is **GCP-first**. Catalogue entries, CIS mappings, the IAM compatibility matrix (Appendix A), and stack-specific Step 10 checks are exhaustive for Google Cloud. AWS and Azure are **secondary**: the skill will surface obvious findings (public S3 buckets, hardcoded credentials, missing tags) but does NOT claim CIS coverage or full provider parity for those clouds. If the codebase is AWS- or Azure-dominant, expect lower recall and treat the report as a starting point rather than an audit.

**Per-cloud rule counts (regenerate via `python3 scripts/detect.py --list-rules | wc -l`):**

| Cloud | Cloud-specific rules | Notes |
|---|---|---|
| **AWS** | 91 | IAM wildcard / `iam_json_policy_analysis` / role privesc, S3 (public access block / server access logging / SSE / versioning), RDS & Aurora (encryption / deletion-protection / backup retention / EOL engine / PITR), KMS, CloudTrail, SQS / SNS / ElastiCache / Redshift / DynamoDB, ECR (scan-on-push / lifecycle), VPC flow logs, EKS (private endpoint / logging / secrets / IRSA), launch-template IMDSv2, GuardDuty, Route53 DNSSEC, SG world-open ports, CloudFront (allow-all / missing logging), Cognito MFA, Secrets Manager rotation, API Gateway access logs, Lambda DLQ / X-Ray, ECS container insights, Module Reuse Advisor (`MOD-REUSE-AWS-VPC-001`). |
| **GCP** | 91 | IAM, KMS, GKE, CloudSQL, BigQuery, Cloud Run, Pub/Sub, GCS, networking (SSH/RDP/database port world-open), Shielded VM, Audit Logs, service-account key creation, Cloud Memorystore Redis auth/TLS, Artifact Registry CMEK, Module Reuse Advisor (`MOD-REUSE-GCP-NETWORK-001`). Full CIS GCP Foundations Benchmark v4.0 coverage for documented controls. |
| **Azure** | 91 | RBAC, storage (versioning/HTTPS), Key Vault (network ACL/key rotation), AKS (Workload Identity / private / authorized IPs / network policy), SQL (firewall/TDE/deprecated single-server/SSL), App Service HTTPS, NSG flow logs, UAMI, ACR admin, subscription activity log, Linux VM password authentication, Module Reuse Advisor (`MOD-REUSE-AZURE-AKS-001`). |
| **Kubernetes / Helm** | 18 | Helm release `set { }` overrides (`SEC-K8S-HELM-001`, `-002`); `kubernetes_*` resource hardening (PSA, network policy, cluster-admin RoleBindings). |
| **Cross-cloud / engine** | 62 | Secrets in HCL/tfvars, provisioner usage, module pinning / supply-chain refs / staleness, `required_providers` version pinning, lifecycle controls (`ROB-DRIFT-001`, `-002`), `count`/`for_each` anti-patterns including `ROB-FOREACH-002` keyset stability, orphan modules (`MOD-UNUSED-001`), variable validation, sensitive outputs, provider aliases, backends, Vault data sources, `applies_when` provider-version gating. |

AWS / GCP / Azure are at numerical parity (91 rules each). **Total: 353 catalogue rules** (351 active + 2 stubs; `--list-rules` reports the 351 active). Re-run `python3 scripts/detect.py --list-rules` for the full live enumeration. README.md's "Rules at a glance" table is the maintained per-cloud breakdown.

When a finding fires against an AWS or Azure resource and the catalogue doesn't have a stable ID for it, tag it as **EXPLORATORY** (per the architecture section below) — not as a regression in the next run.

---

## Architecture: detection vs judgement

The skill operates in two passes for **all modes except verify-fixed and self-test**:

1. **Detection pass** — apply every catalogue pattern to every `.tf` file in scope. Output: a deterministic set of `(file, line, catalogue_id)` triples. Uses Grep + simple HCL attribute lookups, no LLM judgement. This pass is reproducible across runs.
2. **Judgement pass** — for each detection, apply the catalogue's `default_urgency`, evaluate any `escalation` rules (cost-aware, environment-aware), apply suppressions, collapse duplicates, contextualize against CLAUDE.md, and write the finding's body. This pass uses LLM judgement.

Splitting detection from judgement makes delta-tracking and verify-fixed reliable: the `(file, catalogue_id)` join key is stable across runs even when the prose body drifts.

For findings the catalogue does not yet cover (novel patterns the agent identifies during reading), tag them as `EXPLORATORY` in the report and flag them for catalogue inclusion in a follow-up. Exploratory findings do NOT carry stable IDs and are excluded from delta tracking — by design.

**Draft-and-challenge for EXPLORATORY findings:**
Before including any novel (non-catalogue) finding in the report, apply the following three-question challenge. A finding that fails **any** check must NOT be included in the report and must NOT be promoted to a stub:

1. **Concrete evidence** — Can you cite a specific `file:line` that unambiguously demonstrates the pattern? If the evidence is "I didn't see X anywhere in the codebase", that is a `resource_absent` pattern — write a catalogue entry (or note it for follow-up) instead of an exploratory finding.
2. **Context sensitivity** — Does `CLAUDE.md`, the repo's `README`, or a `.tf-analyze-ignore.yaml` document this as an intentional pattern or compensating control? If yes, downgrade to **INFO** or discard. Do not penalise intentional architectural choices.
3. **Generalisability** — Would this pattern fire on a well-configured reference implementation of the same resource type (for example, the provider's own Getting Started guide)? If yes, the finding is likely caused by missing context, not a real risk — discard it.

Exploratory findings that pass all three checks are included under a dedicated **"Exploratory Findings (unverified)"** subsection placed at the **end** of the report, after all catalogue-backed sections. Each entry must include:
- The `file:line` evidence from question 1
- A one-sentence answer to each of the three challenge questions
- A proposed catalogue ID (e.g., `EXP-SEC-001`) for follow-up

This section is clearly labelled: *"These findings have not been validated by the detection catalogue. They carry no stable IDs and are excluded from delta tracking."*

**Auto-stub generation:** `detect.py --auto-stub <dir>` scaffolds catalogue YAML stubs for IDs that are *not* in the active catalogue. Two drivers:

1. **Judgement-pass promotion (primary):** After the judgement pass identifies exploratory findings, pass their proposed IDs via `--propose-stub EXP-FOO-001,EXP-BAR-002`. The script writes one YAML per ID with `status: stub` and `TODO` placeholders.
2. **External reconciler:** If findings arrive from an external tool (tflint, tfsec) with IDs the catalogue doesn't cover, `--auto-stub` creates a stub automatically.

Stubs are skipped by default during normal scans (`status: stub` is filtered in `load_catalog`). Use `--include-stubs` only when validating the YAML parses. Promote a stub by editing the YAML to `status: active`, adding a real detection pattern, writing a fixture under `fixtures/<name>/` referenced in `fixtures:`, and re-running `scripts/self_test.py`.

In the report, note any new stubs under the **"Catalogue follow-ups"** section so the next operator can triage them.

**`resource_arg` match modes — `regex` vs `not_regex`:** The `resource_arg` pattern kind supports two mutually-exclusive match modes that can both appear in the same `patterns:` list:

- `regex` — fires when the attribute **value matches** the pattern. Use for "must equal exactly this value" checks (e.g., `auth_enabled = false`). **Important:** `block_arg_value` strips surrounding quotes from simple string attributes, so write `regex: 'DISABLED'` not `regex: '"DISABLED"'` for a value like `transit_encryption_mode = "DISABLED"`. Boolean and list values are not stripped.
- `not_regex` — fires when the attribute is present but its value **does not match** the pattern. Use for partial-config detection: `not_regex: '"audit"'` on `enabled_cluster_log_types` fires when the list value doesn't contain the string `"audit"`. List values retain their surrounding brackets and inner quotes, so include the double-quote characters in the pattern.

Both modes require at least one of `regex` or `not_regex`. When both are present in a single pattern entry, they are OR-combined (either condition fires the rule).

**`iam_policy_analysis` pattern kind** *(new in Round 24)*: walks every `data "aws_iam_policy_document"` block and inspects each `statement {}`. Companion `iam_json_policy_analysis` *(new in Round 26)* parses inline `policy = jsonencode({...})` on `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, and `aws_iam_group_policy` — closes the historic uncovered case where teams build the policy directly rather than via the data-source pattern. Statements with `effect = "Deny"` are skipped in both kinds — only `Allow` statements are examined. The `check:` field selects what to look for:

| `check`                            | Fires when                                                              |
|------------------------------------|-------------------------------------------------------------------------|
| `wildcard_action`                  | `actions` list contains `"*"`                                           |
| `wildcard_resource`                | `resources` list contains `"*"`                                         |
| `public_principal`                 | any `principals { identifiers = [..., "*", ...] }` block                |
| `wildcard_action_iam`              | any `iam:*` action (privesc class)                                      |
| `wildcard_action_and_resource`     | both `actions` and `resources` contain `"*"` in the same statement      |
| `not_action_or_not_resource`       | uses `not_actions` or `not_resources` on an Allow statement             |

See `catalog/SEC-AWS-IAM-POLICY-001..006.yaml` (data-source) and `catalog/SEC-AWS-IAM-JSON-001..004.yaml` (inline JSON) for shipped instances.

**`helm_set_value` pattern kind** *(new in Round 26)*: walks every `resource "helm_release" "..." { set { name = "..."; value = "..." } }` block and fires when the (name, regex) pair matches. Lets the catalogue express "this chart override is unsafe" without needing every chart's value schema. Pattern fields: `name:` (exact key like `service.type`) and `regex:` (against the value). See `catalog/SEC-K8S-HELM-001..002.yaml`.

**`applies_when:` rule gating** (engine support since Round 1; documented here): catalogue rules can declare `applies_when: { min_provider: { aws: "5.0" }, min_terraform: "1.6" }`. Rules whose constraints can't be satisfied by the repo's `required_providers` / `required_version` are silently skipped, with a stderr count. Use this when a rule depends on attributes added in a specific provider version (e.g. `ssl_mode` was added in google provider 5.x).

**`policy` pattern kind** *(new in Round 33)*: the only kind that sees **more than one resource at a time** — for cross-resource, conditional, and aggregate rules the single-resource kinds above can't express. The pattern carries `match:` (which resources bind, as `resource`), exactly one of `require:`/`forbid:` (the assertion — `require` fires when false, `forbid` when true), and an interpolated `description:`. The predicate language is `and/or/not`, comparisons (`== != < <= > >= in "not in" matches`), `has(path)`, and `exists/all/none/count(TYPE where PRED)` quantifiers over `resource.type/.name/.attr.<path>/.tags.<key>` (`that` is the candidate inside a quantifier). It's a hand-rolled parser/evaluator — **no `eval`**, so a `--catalog` user file can't execute code. Expressions are compile-checked at catalogue load (`--strict-catalog`). v1 runs on the regex parser with best-effort scalar/list/bool coercion (repeated blocks bind to the first; computed values stay unresolved — use `--plan-json` for those; graph predicates are phase 2). Full authoring guide: **`docs/policy-dsl.md`**.

---

## Urgency Levels

Every finding MUST be assigned one of these urgency levels:

| Level | Label | Meaning |
|-------|-------|---------|
| 1 | **CRITICAL** | Security vulnerability, data loss risk, or correctness bug that could cause outages. Fix immediately. |
| 2 | **HIGH** | Violates established best practices in a way that will cause pain at scale — missing state locking, hardcoded credentials, no validation on dangerous inputs. Fix this sprint. |
| 3 | **MEDIUM** | Maintainability or robustness issue — duplicated blocks, missing descriptions, overly broad IAM roles. Plan to address. |
| 4 | **LOW** | Style nit, minor inconsistency, or improvement opportunity. Address opportunistically. |
| 5 | **INFO** | Observation or positive finding worth noting. No action required. |

## Blast Radius

Every finding MUST also be tagged with blast radius:

| Tag | Meaning |
|-----|---------|
| `single-resource` | Affects one resource only |
| `module` | Affects an entire module or its consumers |
| `environment` | Affects one deployment environment |
| `infrastructure-wide` | Affects all environments, all services (e.g., PKI root CA, state backend) |

## Suppression

Suppressions are applied at **both** the detection pass (via `detect.py --suppress`) and the judgement pass. The detection pass handles two suppression sources:

**Inline comments:** `# tf-analyze:ignore <CATALOGUE-ID>` on the same line or the line above a finding suppresses it for that specific location.

**Pattern-level suppression** *(catalogue-author concern, not user-facing)*: catalogue patterns of kind `resource_arg`, `resource_missing_arg`, and `hcl_attr` accept `suppress_if_body_contains: '<substring>'`. The pattern is skipped on any resource whose body contains the substring. Use sparingly — for clearly-defined alternative-correct shapes (e.g. an HTTP listener's `type = "redirect"` default action). Does not affect user-facing suppression.

**Provider-level `default_tags` propagation**: when a directory's AWS provider declares `default_tags { ... }`, `aws_*` rules whose target arg is `tags` (or any `tags.*` path) are skipped — the provider injects the tags downstream so a missing-tags finding would be a false positive.

**File-based suppressions:** `.tf-analyze-ignore.yaml` in the repo root (or target directory):

```yaml
suppressions:
  - id: SEC-PROVIDER-001
    reason: "Intentional — IAP tunnel requires insecure_https for localhost"
    expires: "2026-06-01"  # optional
```

Expired suppressions (date < today) are treated as active findings. Pass `--no-suppress` to `detect.py` to disable all suppression and show every finding.

Suppressed findings MUST still appear in the report under a dedicated **"Suppressed Findings"** section (not hidden), showing the suppression reason.

## CI Integration

The detection pass supports CI gating via exit codes and multiple output formats:

- **`--fail-on LEVEL`** — exit with code 1 if any finding at the given urgency or above exists. Example: `detect.py --target . --fail-on HIGH` fails CI on any HIGH or CRITICAL finding but passes on MEDIUM/LOW/INFO.
- **`--format sarif`** — SARIF v2.1.0 JSON for GitHub Actions Code Scanning, Azure DevOps, or any SARIF-compatible CI system. The emitter attaches `helpUri` (catalog YAML on GitHub), `help.markdown` (recommendation text), `partialFingerprints` (sha256 of `id|file|resource` — stable when prose drifts but **not** stable across file moves; a renamed file emits a RESOLVED + NEW pair), `security-severity` scores (9.5/7.5/5.0/3.0/1.0 for CRITICAL/HIGH/MEDIUM/LOW/INFO), and CIS control tags for controls-mapped findings.
- **`--format html`** — self-contained HTML report with collapsible `<details>` per catalogue ID and urgency-colored badges. Right for human review of large findings lists — use alongside `--format sarif` in CI to publish both as workflow artifacts.
- **`--compare <prior.json>`** — compare against a prior `--format json` report and output a delta (new, resolved, unchanged). Useful for PR comments showing what changed.
- **`--auto-compare`** — auto-discover the most recent `tf-analysis-*.json` under `reports/` as the comparison baseline. Preferred over manual `--compare` for scheduled runs.
- **`--mode diff [--diff-base REF]`** — per-file scans restricted to `.tf` files changed since `REF` (auto-detected as `main` or `master`). Corpus-level checks still run against the whole tree but filter to changed files. Best for PR CI — drops scan time from seconds to milliseconds.
- **`--no-suppress`** — disable all suppression for audit runs that must see every finding.
- **`--plan-json PATH`** — accept a pre-generated `terraform show -json plan.tfplan` file. Rules that support plan-time evaluation (`resource_arg`, `resource_missing_arg`, `resource_present`, `hcl_attr`, `data_source_present`) are re-evaluated against the plan's resolved values. Findings are tagged `mode=plan` so reports can distinguish them from static findings. Use this in CI when a separate job with credentials generates the plan and saves it as an artifact — the analysis job then runs without credentials. Required for detecting variable-resolved violations (e.g., a tfvar setting an IAM role to a forbidden value).
- **`--check-registry`** — query `registry.terraform.io` for the latest published version of every registry-style module source and emit `MOD-STALE-001` findings for modules significantly behind. Off by default (requires outbound HTTPS). Safe to enable in CI runners with internet access.
- **`--compliance-framework [cis|pci_dss|soc2|owasp_iac|nist_csf|nist_800_53|csa_ccm|slsa|owasp_top10|owasp_api|owasp_cicd|owasp_llm|owasp_k8s|owasp_asvs|all]`** — choose the compliance standard for `--compliance` output. Default: `cis`. **All 13 modes surface real data** after the R30.9 bulk taxonomy tag (174 rules carry the four new R30.1 fields). Use `all` to combine every framework in one report.
- **`--rank-by [urgency|exploitability|hybrid]`** *(new in R30.2)* — ordering mode for findings. `urgency` (default) keeps the legacy CRITICAL-first ordering. `exploitability` cross-references each rule's `cwe:` tags against CISA's Known Exploited Vulnerabilities catalog, promotes findings whose rule touches a KEV-listed CWE class one urgency tier (LOW→MEDIUM→HIGH→CRITICAL, capped), and sorts KEV hits first. `hybrid` keeps urgency-first ordering with the KEV promotion applied. KEV + FIRST.org EPSS feeds are cached daily at `~/.cache/tf-analyze/` (override with `$TFA_CACHE_DIR`; freshness window via `$TFA_THREAT_INTEL_TTL`). 🔥 KEV badge appears in text output, PR-summary table cell, and SARIF (`exploitability:kev` tag per result). **No comparable OSS IaC scanner integrates KEV today.**
- **`--no-threat-intel`** *(new in R30.2)* — disable network fetches for CISA KEV / FIRST.org EPSS. Falls back to cache if present, otherwise skips KEV/EPSS enrichment cleanly. Required for air-gapped CI.
- **`--explain-score`** *(new in R30.8)* — surface the top-5 findings ranked by score contribution (CRITICAL=15 pts > HIGH=7 > MEDIUM=3 > LOW=1; INFO weight 0 is excluded), with the projected score and grade after each fix is applied. Tells the user **which fix is worth most**. Renders as a header block in text output and a structured `score_explanation` field in JSON output.
- **`--show-fixes`** — render `fix_hcl` snippets from catalogue entries alongside each finding. HTML: dark-themed disclosure widget per finding. Text: indented HCL block below the finding line. In `--mode pr-review`, fix snippets are posted as ` ```suggestion ``` ` blocks — reviewers can apply with one click.
- **`--apply-fixes dry-run`** — preview auto-remediation as a unified diff without writing files. Run this first to review what would change. Safe in CI (read-only).
- **`--apply-fixes apply`** — apply `fix_hcl` patches directly to `.tf` files. Creates `.bak` backups. Handles `resource_missing_arg` (inserts missing attribute before closing `}`) and `resource_arg`/`hcl_attr` (replaces wrong-value line). After applying, re-run `detect.py` to confirm the findings are resolved.
- **`--cache`** — enable incremental scan caching. Writes `.tf-analyze-cache.json` in the target directory keyed on a hash of all `.tf` file contents and catalogue rules. Subsequent runs on unchanged code return cached findings instantly. Use `--cache-file PATH` to override the location. Invalidated automatically when any file or rule changes.
- **`--baseline PATH`** *(new in Round 24)* — load a prior JSON report and suppress findings whose `(id, file, line, resource)` tuple is already present. Only retained findings affect the `--fail-on` exit code; suppressed-by-baseline findings are surfaced under the JSON `suppressed_by_baseline` key. Use to ratchet on legacy repos: snapshot once, gate on no-regressions thereafter.
- **`--format mitre`** *(updated in the 2026-05-10 sweep)* — group findings by **ATT&CK tactic → technique** using catalogue `mitre:` fields. Output uses the canonical kill-chain order (Initial Access → Execution → ... → Impact); each technique is rendered with its human name (`T1078.004 — Valid Accounts: Cloud Accounts`), not just the bare ID. Pinned against ATT&CK v17 via `MITRE_ATTACK_VERSION` in `detect.py`. Findings without a mapping fall into a final `(unmapped)` group so coverage gaps stay visible. SARIF output additionally tags every finding with `cis:`, `mitre:Tnnnn`, `cwe:CWE-<n>`, and `d3fend:D3-<TOKEN>` properties — GitHub Code Scanning consumers can filter by any of the four taxonomies.
- **`--mitre-tactic <tactic>`** *(new in the 2026-05-10 sweep)* — restrict `--format mitre` output to one ATT&CK tactic. Case-insensitive, separator-tolerant (`initial-access`, `Initial Access`, and `INITIAL_ACCESS` are all equivalent). Powers tactic-scoped audits ("show me only the Defense Evasion findings on this branch").
- **`--no-hcl2`** *(new in Round 24)* — disable the python-hcl2 fast-path (which is now ON by default when the dependency is installed). Use for benchmarking or in stdlib-only environments. Equivalent env var: `TF_ANALYZE_NO_HCL2=1`. The legacy `--use-hcl2` flag still works but is now a no-op.
- **`--show-info`** *(new with module-reuse advisor)* — render INFO-tier findings (advisory; e.g. module-reuse suggestions). Default off — INFO findings are still counted in `summary.counts.INFO` but are filtered out of the rendered output so they don't drown the signal. INFO carries weight 0 in the score formula, so this flag only affects display, not gating.

Ready-to-use configs for pre-commit and GitHub Actions live under `integrations/`. The GitHub Actions workflow (`integrations/github-action.yml`) now includes a PR comment fallback that posts findings as a collapsible comment on every pull request — works on free-tier repos that don't have Code Scanning enabled.

### `python-hcl2` fast-path (default-on since Round 24)

By default `detect.py` enables the python-hcl2 fast-path when the
dependency is installed (the Docker image bundles it). When it isn't,
the regex parser is used and a one-line stderr notice is emitted. A
known limitation of the regex parser is that heredoc-bearing attributes
(`user_data = <<-EOF\n...\nEOF`) return `None` from `block_arg_value`,
so any check looking at the value of such an attribute silently misses.

Pass `--use-hcl2` (or set `TF_ANALYZE_USE_HCL2=1`) to enable an optional
fast-path that uses [`python-hcl2`](https://pypi.org/project/python-hcl2/)
for heredoc-aware extraction. If `python-hcl2` isn't installed, the flag
prints a one-line warning and the regex path is used unchanged — so the
default behaviour is preserved and the flag is safe to set globally in
CI. Install with `pip install python-hcl2` once on the runner; the
performance overhead is negligible because it only kicks in for blocks
that contain `<<` (the regex path stays the default for everything else).

This is the extension point for richer hcl2-backed detectors. Add new
checks under the existing `pattern_kind` system; call
`_hcl2_block_arg_value` (or load the parse tree directly via
`hcl2.load`) when the check needs structural awareness regex can't give.

---

## Step 0: Pre-Analysis — Credential Scan and Hygiene (RUNS FIRST)

**This step MUST complete before any other analysis.** If CRITICAL credential findings are detected, flag them prominently at the top of the report.

### 0a. Credential pattern detection in tfvars

Scan ALL `.tfvars` files on disk (even gitignored ones) for patterns matching real credentials:

| Pattern | What it catches |
|---------|----------------|
| `sk-ant-` | Anthropic API keys |
| `sk-proj-`, `sk-live-`, `sk-test-` | OpenAI / Stripe keys |
| `ghp_`, `ghs_`, `gho_` | GitHub tokens |
| `AKIA[0-9A-Z]{16}` | AWS access key IDs |
| `eyJhbG` | Base64-encoded JWTs |
| 40+ character hex strings | Generic secrets (HCP, Vault tokens) |
| UUID format with hyphens | Consul/Vault bootstrap tokens |
| Base64-encoded JSON with `"type": "service_account"` | GCP SA key files |

If credentials are found, report them as **CRITICAL** with the instruction to rotate immediately. Do NOT print the actual credential values in the report — reference them by type and file:line only.

### 0b. Git history credential leak check

```bash
git log --all --diff-filter=A --name-only --pretty=format: -- '*.tfvars' '*.tfstate' '*credentials*' '*.pem' '*.key' 2>/dev/null | sort -u | head -20
```

If any `.tfvars` or `.tfstate` files appear in git history, flag as **HIGH** — the secret lives forever in history even if the file is now gitignored. Recommend `git filter-repo` or BFG Repo Cleaner.

### 0c. State file detection on disk

```bash
find <PATH>/.. -name '*.tfstate' -o -name '*.tfstate.backup' 2>/dev/null | grep -v '.terraform/'
```

Flag any results as **CRITICAL** — state files contain decrypted secrets for every managed resource.

### 0d. Lock file and provider integrity

- Check if `.terraform.lock.hcl` exists. If absent, flag as **HIGH**.
- Check if `.terraform.lock.hcl` is in `.gitignore`. If gitignored, flag as **HIGH** — the lock file MUST be committed for provider version consistency.
- Compare `required_version` in `versions.tf` against `terraform version` output. Flag mismatches as **MEDIUM**.

### 0e. Read project documentation

Before analyzing any `.tf` files, read these files if they exist (do NOT skip this):
- `CLAUDE.md` (or `README.md`) — understand architectural intent, known workarounds, operational rules
- `Taskfile.yml` (or `Makefile`, `Justfile`) — understand the deploy workflow, phase-gating, manual steps
- `.tf-analyze-ignore.yaml` — load suppression rules

Build a list of **intentional patterns** from the documentation (e.g., "`insecure_https = true` is an IAP tunnel workaround", "`lifecycle { ignore_changes = [data] }` is managed by Taskfile"). Reference this list during analysis to avoid false positives. When a finding matches a documented intentional pattern, downgrade it to **INFO** with a note: "Documented as intentional in CLAUDE.md — verify still applicable."

---

## Step 1: Discovery

Find all Terraform files in scope:

```bash
find <PATH> -name '*.tf' -o -name '*.tfvars' | grep -v '.terraform/' | sort
```

Count files, modules, and scenarios. Build a map of:
- Module directories (contain `main.tf` or `variables.tf`)
- Scenario/root directories (contain `provider` or `terraform` blocks)
- Variable files (`.tfvars`, `variables.tf`)
- Output files (`outputs.tf`)
- Template files referenced by `templatefile()` calls (`.tpl`, `.tmpl`)
- Orphaned modules (module directories that no scenario `source =` references)

Also count resources per module to identify oversized modules.

**Read all `.tf` files in parallel batches of 4-6 files** to maximise efficiency. Do not read files sequentially one at a time.

Report the scope summary at the top of the analysis.

### 1a. Subagent delegation for large repos

Choose the reading strategy based on file count:

| File count | Strategy |
|---|---|
| < 30 `.tf` files | Sequential reads in the main agent |
| 30–100 `.tf` files | Parallel reads (4–6 at a time) in the main agent — subagent overhead exceeds benefit |
| > 100 `.tf` files **with `focus:all`** | Parallel subagents per focus area (see below) |
| > 100 `.tf` files **with a single `focus:`** | One subagent for that focus area |

When `focus:all` is requested on a repo with more than 100 `.tf` files, dispatch all focus areas in a single message as parallel subagents:

```text
# Send all six as one Agent tool call with multiple invocations:
Agent(subagent_type="Explore", description="Security scan",
      prompt="Scan all .tf files under <path> for patterns in SKILL.md Step 2
              (Security Posture). Report each hit as JSON:
              {file, line, catalogue_id_or_EXPLORATORY, excerpt, one_line_justification}.
              Do not assign urgency — parent agent will do that.")

Agent(subagent_type="Explore", description="DRY/reuse scan",
      prompt="... Step 3 (DRY and Code Reuse) ...")

Agent(subagent_type="Explore", description="Style scan",
      prompt="... Step 4 (Style and Conventions) ...")

Agent(subagent_type="Explore", description="Robustness scan",
      prompt="... Step 5 (Robustness) ...")

Agent(subagent_type="Explore", description="Ops scan",
      prompt="... Step 7 (Operational Readiness) ...")

Agent(subagent_type="Explore", description="CI/CD scan",
      prompt="... Step 8 (CI/CD and Testing Maturity) ...")
```

**Parent agent synthesis after all subagents complete:**
1. Collect all subagent JSON outputs.
2. De-duplicate on `(file, line, catalogue_id)` — the same pattern may appear in multiple subagent results.
3. Run Steps 9 (Cross-Module Contracts) and 10 (Stack-Specific) **in the parent agent** — these require global visibility across all files that individual subagents can't provide.
4. Run Steps 11–17 (judgement, cost, report generation) in the parent agent on the merged finding set.

**Output schema each subagent must return (structured JSON list):**
```json
[
  {
    "file": "path/to/resource.tf",
    "line": 42,
    "id": "SEC-GCP-IAM-001",
    "excerpt": "  member = \"allUsers\"",
    "justification": "IAM binding grants public access to all authenticated users"
  }
]
```
Using this schema allows the parent agent to merge results mechanically without re-reading the files.

### 1b. Build a dependency graph from `terraform graph` (static-mode capable)

`terraform graph` runs without GCP/AWS credentials in most repos — it only needs the providers downloaded by `terraform init -backend=false`. The output is a DOT description of every resource and the references between them. Capture it once during discovery and reuse it throughout the analysis.

```bash
terraform -chdir=<TARGET_DIR> init -backend=false -input=false >/dev/null
terraform -chdir=<TARGET_DIR> graph -type=plan 2>/dev/null > /tmp/tf-analyze-graph.dot \
  || terraform -chdir=<TARGET_DIR> graph 2>/dev/null > /tmp/tf-analyze-graph.dot
```

Parse the DOT to extract:
- **Node list** — every resource address managed by this configuration. Cross-reference with the `.tf` files to detect orphaned `resource` blocks (declared but not in graph) or graph nodes that don't appear in any file (impossible in static mode, but worth flagging).
- **Edge list** — every reference between resources. Used directly by Section 9d (dependency-graph bottlenecks): a node with ≥10 incoming edges is a chokepoint.
- **Module boundaries** — graph nodes namespaced as `module.X.Y` reveal the actual module instantiation tree without parsing `source =` paths.

Save the parsed graph to a structured form so Section 9d, Section 5e (conditional reference safety), and Step 12 (plan-mode analysis) can reuse it without re-parsing.

If `terraform graph` fails (e.g., the repo cannot init without credentials, or providers are not in the lock file), fall back to grep-based reference detection and note in the report that the dependency-graph analysis ran in degraded mode.

### 1c. Create the sentinel tempdir

Step 14 (Recommendation Verification) needs a working `terraform init`-ed directory to validate proposed fixes. Initializing once and reusing the directory throughout the run is ~30× faster than re-initing per recommendation.

**Critical: persist the path to a file, not an env var.** Each invocation of the `Bash` tool gets a fresh shell, so `export TF_ANALYZE_SENTINEL=...` set in this step does **not** survive into Step 14a or Step 17. Write the absolute path to `/tmp/tf-analyze-sentinel.path` instead, and have downstream steps read it back.

```bash
SENTINEL=$(mktemp -d -t tf-analyze-sentinel.XXXX)
cp <TARGET_DIR>/versions.tf "$SENTINEL/versions.tf"
# If providers must come from cache, also copy .terraform.lock.hcl
cp <TARGET_DIR>/.terraform.lock.hcl "$SENTINEL/.terraform.lock.hcl" 2>/dev/null || true
if terraform -chdir="$SENTINEL" init -backend=false -input=false >/dev/null 2>&1; then
  echo "$SENTINEL" > /tmp/tf-analyze-sentinel.path
else
  echo "WARN: sentinel init failed — Step 14a will run in degraded mode"
  rm -rf "$SENTINEL"
  rm -f /tmp/tf-analyze-sentinel.path
fi
```

Step 14a then re-reads the path:

```bash
SENTINEL=$(cat /tmp/tf-analyze-sentinel.path 2>/dev/null || true)
if [ -n "$SENTINEL" ] && [ -d "$SENTINEL" ]; then
  # validate proposed HCL against the init-ed providers
  ...
fi
```

If init fails (no providers cached, network unavailable, locked provider missing), the path file isn't written and Step 14a falls back to Appendix A lookups only. Do not block the rest of the run on this — most recommendations can be verified via the matrix.

Cleanup at the end of Step 17:

```bash
SENTINEL=$(cat /tmp/tf-analyze-sentinel.path 2>/dev/null || true)
[ -n "$SENTINEL" ] && [ -d "$SENTINEL" ] && rm -rf "$SENTINEL"
rm -f /tmp/tf-analyze-sentinel.path
```

---

## Step 2: Analyze — Security Posture

Examine every `.tf` file in scope for:

### 2a. Credentials and secrets
- Hardcoded secrets, API keys, tokens, passwords in `.tf` or `.tfvars` (excluding `*.auto.tfvars` in `.gitignore`)
- Variables holding sensitive data missing `sensitive = true`
- Secrets passed as default values on variables
- `.tfvars` files containing secrets that are tracked in git (check `.gitignore`)
- Secrets in `templatefile()` template sources (`.tpl` files) — scan referenced templates
- `local_file` or `local_sensitive_file` resources that write secrets to disk
- `null_resource` / `terraform_data` provisioners that might echo or curl secrets → **SEC-PROVISIONER-001**
- Vault policy HCL strings (embedded in `vault_policy` resources) that reveal sensitive secret paths
- Outputs that reference sensitive values without being marked `sensitive = true` → **SEC-SENSITIVE-001**
- Sensitive variables passed to module inputs where the receiving variable is NOT marked sensitive → **SEC-SENSITIVE-002**

### 2b. IAM and access control
- Overly broad IAM roles (`roles/owner`, `roles/editor`, `roles/admin`, `*Admin`) → **SEC-GCP-IAM-001** | CIS 1.6
- `allUsers` or `allAuthenticatedUsers` in any IAM binding → **SEC-GCP-IAM-002** | CIS 5.1, 7.1
- IAM bindings at project level that should be at resource level (consult Appendix A first)
- Service accounts with more permissions than their usage requires
- Missing `condition` blocks on IAM bindings where appropriate
- Service account impersonation chains — trace A→B→C to detect transitive privilege escalation
- Custom roles with wildcard (`*`) permissions
- `google_service_account_key` resources without lifecycle rotation → CIS 1.4
- Workload Identity binding correctness — is the K8s SA→GCP SA mapping bidirectional?

**CRITICAL — before recommending "scope this binding to resource X":** consult the IAM compatibility matrix in **Appendix A**. Not every Google/AWS/Azure resource exposes resource-level IAM in its provider. Recommending `google_workflows_workflow_iam_member`, for example, will fail at `terraform validate` because that resource type does not exist in the `google` provider. If a service is not in the matrix, default to "keep at project level" and use IAM Conditions (`role_binding.condition { expression = ... }`) or service-account narrowing instead. See **Step 13: Recommendation Verification** for the validate-before-recommending workflow.

### 2c. Network security
- SSH (`tcp:22`) firewall rules with source `0.0.0.0/0` → CIS 3.6
- RDP (`tcp:3389`) firewall rules with source `0.0.0.0/0` → CIS 3.7
- Other ports exposed to `0.0.0.0/0` without explicit justification
- Default VPC in use (`google_compute_network.default` referenced) → CIS 1.14, 3.1
- DNSSEC disabled on Cloud DNS managed zones → CIS 3.9
- DNSSEC using RSASHA1 KSK or ZSK → CIS 3.10, 3.11
- Public IPs assigned to compute instances → CIS 4.8
- Compute instances with `can_ip_forward = true` → CIS 4.11
- Plaintext protocols where encrypted alternatives exist (HTTP vs HTTPS, no TLS)
- LoadBalancer services without `loadBalancerSourceRanges` restrictions
- Firewall rules allowing all protocols (`allow { protocol = "all" }`)
- Cloud NAT logging configuration (is it enabled? errors-only or all?)
- VPC flow logs sampling rate and metadata inclusion → CIS 3.8

### 2d. State and backend security
- Remote backend without encryption or access controls
- State files stored locally or in git
- Missing state locking configuration
- Sensitive outputs not marked `sensitive = true` → **SEC-SENSITIVE-001**
- GCS state bucket without versioning enabled → CIS 5.3
- GCS state bucket without `uniform_bucket_level_access` → CIS 5.2
- GCS state bucket without customer-managed encryption keys (CMEK) — flag as INFO if using default Google-managed encryption
- State bucket IAM — who has `roles/storage.objectViewer` on the state bucket?

### 2e. Provider configuration
- Providers pinned to `>=` without upper bounds (allows breaking changes) → **SEC-PROVIDER-001**
- Missing provider version constraints entirely → **SEC-PROVIDER-001**
- Credentials in provider blocks instead of environment variables
- Provider aliases that might connect to unexpected backends
- Safety-bypass flags (`skip_metadata_api_check`, `skip_region_validation`, `insecure_https = true` on non-localhost addresses)

### 2f. Encryption at rest
- GCS buckets without customer-managed encryption keys (CMEK)
- GKE clusters without Application-layer Secrets Encryption (`database_encryption.state = "ENCRYPTED"` block) → CIS 8.5.5
- GKE node pools without CMEK boot disks → CIS 8.6.4
- Compute VM disks for critical instances not encrypted with CMEK → CIS 4.7
- BigQuery datasets / tables not encrypted with CMEK → CIS 7.2, 7.3
- KMS key rotation period > 90 days → CIS 1.10
- Cloud SQL instances without encryption configuration
- Vault transit encryption for sensitive data at application level

### 2g. Logging and audit (NEW)
- VPC Flow Logs disabled on any subnet → CIS 3.8
- Cloud Audit Logs not configured (check for `google_project_iam_audit_config`) → **SEC-GCP-LOGGING-001** | CIS 2.1
- GKE clusters without `logging_service = "logging.googleapis.com/kubernetes"` → CIS 8.7.1
- Missing `vault_audit` resource (is Vault auditing enabled?)
- Cloud NAT logging disabled or set to ERRORS_ONLY for production environments

### 2h. Kubernetes security contexts (NEW)
For all `kubernetes_deployment`, `kubernetes_pod`, `kubernetes_daemon_set`, `kubernetes_stateful_set` resources:
- Containers running as root (`run_as_user = 0` or missing `run_as_non_root = true`)
- Missing `security_context` blocks entirely
- `privileged = true` or `allow_privilege_escalation = true`
- Missing `capabilities { drop = ["ALL"] }`
- `host_network = true`, `host_pid = true`, or `host_ipc = true`
- Missing `readiness_probe` / `liveness_probe` on main containers
- `image_pull_policy = "Always"` on init containers (wastes bandwidth; should be `IfNotPresent`)
- Secrets mounted as environment variables via plain `env { value = ... }` instead of `secretKeyRef`

### 2i. Supply chain security
- Module sources from arbitrary git URLs without commit pinning (`ref=`) → **MOD-PIN-001**
- Registry modules without `version` constraint → **MOD-PIN-001**
- Unpinned `source` paths for local modules (acceptable but note if paths are fragile)
- Use of `http` data source to fetch arbitrary URLs (potential data exfiltration)
- `.terraform.lock.hcl` hash integrity — if present, verify it lists all required providers
- Providers from third-party (non-HashiCorp) registries — flag for review, not necessarily a violation

### 2j. Sensitive data flow tracing → SEC-SENSITIVE-001, SEC-SENSITIVE-002, SEC-SENSITIVE-003
Trace the propagation of sensitive values through the module graph:
- Walk all `module.X.output_name` references in scenario and parent-module files
- For each reference, locate the source output in the child module's `outputs.tf`
- If the source output has `sensitive = true`, verify the receiving variable in the calling module also has `sensitive = true`
- Flag mismatches as **HIGH** — sensitive values without the `sensitive` marker leak plaintext in `terraform plan` and `terraform output` console output
- Also check the reverse: variables marked `sensitive = true` passed to module inputs where the module's corresponding variable is NOT marked sensitive — the sensitivity is silently dropped inside the child module → **SEC-SENSITIVE-002**
- **`templatefile()` leaks** (`SEC-SENSITIVE-003`): the detection pass flags `templatefile()` calls whose argument map references a `sensitive = true` variable. The rendered output is a plain string that Terraform does NOT mark as sensitive, so the secret appears in plans, state, and logs.
- Trace chains up to 3 levels deep (scenario → module → sub-module). Beyond that, flag as **MEDIUM** — deep nesting makes sensitivity auditing unreliable

### 2k. Provisioner usage → SEC-PROVISIONER-001
Flag any `provisioner "local-exec"` or `provisioner "remote-exec"` block as **HIGH**. Provisioners execute arbitrary shell commands outside Terraform's resource model — they are not tracked in state, cannot be planned, and are a common vector for credential leakage. The detection pass uses grep patterns against all `.tf` files.

### 2l. Dangerous data sources → SEC-DATASOURCE-001
Flag `data "external"` and `data "http"` blocks as **MEDIUM**. `data.external` runs an arbitrary program at plan time and trusts its JSON output. `data.http` fetches a URL at plan time, which may introduce non-determinism or leak plan context. Both are legitimate but should be reviewed — especially `data.external` in shared modules where contributors may not realize a plan triggers shell execution.

---

## Step 3: Analyze — DRY and Code Reuse

### 3a. Duplicated blocks
- Near-identical resource blocks that should use `for_each` or `count`
- Repeated variable definitions across modules with same name/type/description
- Copy-pasted `provider`, `backend`, or `terraform` blocks
- Inline values that appear 3+ times and should be locals
- Repeated `depends_on` lists that should be structured differently
- Repeated `lifecycle { ignore_changes = [...] }` blocks with identical entries

### 3b. Module structure
- Flat root modules that should be decomposed into child modules
- Modules that do too many things (>15 resources) and should be split
- Resources that are candidates for shared modules but exist as one-offs
- Modules that re-implement what a well-maintained registry module already provides — **automated via the `module-reuse` rule section.** The engine fingerprints each directory's resource cluster against popular community modules (`MOD-REUSE-AWS-VPC-001`, `MOD-REUSE-GCP-NETWORK-001`, `MOD-REUSE-AZURE-AKS-001` today). Findings are INFO tier, so they don't gate CI; render with `detect.py --show-info` or open the **Module Reuse Advisor** panel in the VS Code extension. Each finding carries a structured `roi` field — `{bespoke_lines, replacement_lines, lines_saved, pct_saved, resource_count}` — so the advisory is actionable ("you'd save ~85 lines / 87% by adopting this module") rather than abstract. The plain-text `context` string also embeds an ROI hint for PR-comment / CLI consumers. New community modules are added by dropping a catalogue YAML with `kind: registry_fingerprint` plus a `fingerprint:` block (required types + supporting types + threshold + exclusions).
- Orphaned modules — defined in `tf/modules/` but never called from any scenario

### 3c. Variable and output patterns
- Variables defined but never referenced
- Outputs defined but never consumed by any caller
- Identical output definitions across modules
- Missing `for_each` on module calls where the same module is instantiated multiple times with similar inputs
- Variable pass-through chains (scenario var → module var → sub-module var, all identical name/type/description with no transformation) — flag excessive indirection

### 3d. Environment parity analysis (NEW)
Compare `.tfvars` files across environments within each scenario directory:
- Group all `.tfvars` files by scenario directory (e.g., `dev.tfvars`, `staging.tfvars`, `prod.tfvars`)
- Extract the set of variable keys from each file
- Flag variable keys present in one environment but missing in another:
  - Missing in `prod.tfvars` → **HIGH** (apply will prompt interactively or use a dangerous default)
  - Missing in non-prod → **MEDIUM**
- Flag values that look like cross-environment copy-paste errors:
  - Project IDs, region names, or cluster names from one environment appearing in another (e.g., `project_id = "my-project-dev"` in `prod.tfvars`)
  - Identical CIDR ranges across environments that should be distinct (overlapping networks prevent peering)
- Flag environments where `deletion_protection` or equivalent safety variables are set to `false` in prod → **HIGH**
- If only one `.tfvars` file exists per scenario, note as **INFO** — single-environment setup, parity check not applicable

---

## Step 4: Analyze — Style and Conventions

### 4a. Formatting and naming
- Run `terraform fmt -check -recursive` and report any failures
- Resource names: should use snake_case, be descriptive, follow `{component}_{purpose}` pattern
- Variable names: consistent casing and prefix conventions within the repo
- File organization: are resources grouped logically by file or scattered?
- Shared locals defined in the wrong file (e.g., `local.mcp_servers` in `deployment.tf` consumed by 4 other files — should be in `locals.tf`)

### 4b. Documentation → STYLE-DESC-001
- Variables missing `description` fields → **STYLE-DESC-001** (detection pass flags these automatically)
- Complex modules missing README.md — list each module and whether it has one
- Outputs missing `description` fields → **STYLE-DESC-001** (detection pass flags these automatically)
- Inline comments on non-obvious logic (present or absent where needed)
- Stale comments referencing outdated code paths or removed features

### 4c. Structural consistency
- Inconsistent file naming across modules (e.g., some use `network.tf`, others use `vpc.tf` for the same concept)
- Inconsistent variable ordering (required first, optional second — or not)
- Mix of `count` and `for_each` for the same pattern within a module
- Lifecycle blocks used inconsistently

### 4d. Deprecated argument and resource detection → STK-DEPRECATION-001
Scan for known deprecated patterns by provider. These cause warnings today but will become errors on the next major provider version. The detection pass catches a subset of these via `STK-DEPRECATION-001` (`resource_arg` patterns for `enable_legacy_abac`, `logging_service`, `monitoring_service`, `metadata_startup_script`). The judgement pass should look for additional deprecated patterns beyond what the catalogue covers:

**Google provider (`google` / `google-beta`):**
- `google_container_cluster` with top-level `node_config` block (should use `google_container_node_pool` instead)
- `logging_service` / `monitoring_service` as string values (replaced by `logging_config` / `monitoring_config` blocks in provider v5+)
- `google_compute_instance` with `create_timeout` (replaced by `timeouts` block)
- `google_project_iam_binding` with `members` including `deleted:` prefixes (stale IAM references)
- `google_sql_database_instance` with `settings.authorized_gae_applications` (removed)

**Kubernetes provider:**
- `load_balancer_ingress` attribute (removed in provider v2.0+)
- Resources using removed beta API versions (e.g., `extensions/v1beta1`)

**Helm provider:**
- `helm_repository` resource (removed in Helm provider v2+; use `repository` argument in `helm_release`)

**Vault provider:**
- `vault_generic_secret` resource used for reading secrets (should use `vault_generic_secret` data source instead)
- `vault_auth_backend` with deprecated `path` handling

**General detection:**
- Run `terraform validate` in the target directory and parse output for lines containing `Warning:` and `deprecated` — capture each as a finding
- Cross-reference with the provider changelog if a `.terraform.lock.hcl` is present to determine the installed version

Assign **MEDIUM** to all deprecated usage — they work today but will break on the next provider major version upgrade.

---

## Step 5: Analyze — Robustness

### 5a. Input validation
- Variables accepting dangerous inputs without `validation` blocks → **ROB-VALIDATION-001**
- Missing `type` constraints on variables (bare `any` types) → **ROB-VALIDATION-002**
- No `nullable = false` on variables that must have values
- Default values that could be dangerous in production (e.g., `deletion_protection = false`)
- `required_version` constraint floor too old for skill assumptions → **ROB-VERSION-001**

### 5b. Error handling and lifecycle
- Stateful resources (databases, buckets, disks, PKI CAs, secrets engines) missing `lifecycle { prevent_destroy = true }` → **ROB-GCP-LIFECYCLE-001**
- Stateful resources with `force_destroy = true` → **ROB-GCP-LIFECYCLE-002**
- Missing `depends_on` where implicit dependency detection may fail (e.g., IAM bindings needed before resource creation)
- Resources that would be destroyed and recreated on name change but lack `create_before_destroy`
- Missing `timeouts` blocks on resources known to be slow (GKE clusters, Cloud SQL, Helm releases, etc.)
- `data` source `for_each` over values that depend on resource attributes computed at apply time — these produce confusing "value depends on resource attributes that cannot be determined until apply" errors. Refactor to use a known-at-plan-time map.
- Google provider `add_terraform_attribution_label = true` (default in google 5+) on resources whose label set is also managed externally (e.g., GKE workloads, Dataflow jobs). The auto-injected `goog-terraform-provisioned` label triggers perpetual diffs against external label managers. Set `add_terraform_attribution_label = false` at the provider level when this clash is documented.

### 5c. State management and moved/import blocks → ROB-MOVED-001
- Resources that will cause issues if imported (missing `import` blocks for brownfield resources)
- Moved blocks missing where resource addresses have changed
- Tainted resources or resources that need manual state intervention
- **Stale moved blocks** (`ROB-MOVED-001`): the detection pass flags any `moved` block present in the code. After `terraform apply` has run successfully and the state reflects the new address, the block should be removed. Stale moved blocks accumulate noise and can confuse future readers.
- **Import blocks**: `import` blocks are one-shot — after `terraform apply` imports the resource, the block can be removed. Flag as informational.

### 5c.i Unused variables and outputs → ROB-UNUSED-001, ROB-UNUSED-002
- **Unused variables** (`ROB-UNUSED-001`): variables declared in a module directory but never referenced as `var.X` in any `.tf` file in that same directory. Note: references inside comments and strings are counted (conservative), so the detection may miss some truly unused variables.
- **Unused outputs** (`ROB-UNUSED-002`): outputs declared in a child module but never consumed via `module.X.output_name` by any caller in the repo. Root module outputs are excluded (they may be consumed externally). Only fires for modules called via local `source = "./"` paths — external module outputs are not tracked.

### 5d. Drift and ignore_changes audit → ROB-DRIFT-001 / ROB-DRIFT-002
- The detection pass automatically flags `ignore_changes = all` via `ROB-DRIFT-001` and `ignore_changes = ["*"]` / `ignore_changes = [tags]` via `ROB-DRIFT-002`. The judgement pass should additionally:
- Catalogue EVERY `ignore_changes` block in the codebase. For each one, assess:
  - Is it justified? (Reference CLAUDE.md / project docs read in Step 0e)
  - Does it mask real drift that should be managed?
  - Is it `ignore_changes = all` or the array form `["*"]`? (Flagged as HIGH/MEDIUM by catalogue — the nuclear option that masks all drift)
  - Is it ignoring fields that Terraform should manage (e.g., `labels`, `tags`, `annotations`)? Per-key suppression `tags["LastModifiedBy"]` is the recommended pattern; whole-`tags` suppression silently drops cost-allocation tags, compliance scope tags, and `default_tags` propagation.
- Resources managed by BOTH Terraform AND external tools (e.g., Taskfile runs `vault write` directly, Helm values updated outside Terraform). Flag the dual-management pattern.
- `terraform_data` / `null_resource` with triggers that may not fire reliably

### 5e. Conditional resource reference safety → ROB-COUNTREF-001
- The detection pass flags unguarded `[0]` references to `count`-conditional resources via `ROB-COUNTREF-001`. The pattern detects `resource.name[0].attr` references in files where the resource has a `count` argument, and the referencing line does not contain a ternary `?`, `try()`, `one()`, or `length()` guard.
- `for_each` resources referenced with keys that might not exist in the map
- Conditional resources that reference OTHER conditional resources without matching conditions
- Module outputs that depend on conditional internal resources without null handling

### 5f. Provider version constraint width (NEW)
Assess the width of `~>` and `>=` constraints → **SEC-PROVIDER-001**:
- `>= X.Y` (no upper bound) — flag as **MEDIUM**, allows future major versions with breaking changes
- `~> 5.0` allows 5.0 through 5.999 — very wide, may include breaking changes within major. Flag as **MEDIUM** for production.
- `~> 5.42` only allows 5.42.x — appropriate for production stability.
- `~> 2.0` on rapidly-evolving providers (kubernetes, helm) — flag as **HIGH** since minor versions often break.
Recommend tightening to minor version (`~> X.Y`) for production scenarios.

Also check **module sources** → **MOD-PIN-001**:
- Registry modules without `version = "~> X.Y"` constraint
- Git sources (`git::https://...`) without `?ref=` pin (commit SHA or version tag)

### 5g. Helm release analysis (NEW)
- `set` blocks with sensitive values that should use `set_sensitive`
- Long `set` chains (>20 values) that should use `values` with a YAML file
- Missing `wait = true` or `wait_for_jobs = true` on releases where post-install jobs must complete
- Missing `timeout` on releases that install CRDs or run init jobs
- `create_namespace = true` when the namespace should be managed by Terraform separately
- Helm chart versions unpinned or using `latest`

### 5h. Stale moved block cleanup (NEW)
Find all `moved` blocks in `.tf` files and assess whether they can be removed:
- For each `moved { from = X  to = Y }` block, check whether both `from` and `to` resource types still exist in the current provider schema (the resource type in the address, e.g., `google_compute_instance`)
- If `mode:plan` is active, cross-reference with `terraform state list` output — if only the `to` address exists in state (and `from` does not), the move has been applied and the block is safe to remove
- In static mode, flag all `moved` blocks as **LOW** cleanup candidates — note that they should be removed after confirming the move has been applied in all environments/workspaces
- Flag `moved` blocks where the `from` resource type no longer exists in the provider (e.g., a renamed resource type from a provider major version upgrade) as **MEDIUM** — these will cause confusing errors if someone tries to roll back

### 5i. Data source reliability (NEW)
Assess the reliability and determinism of data sources:
- **`external` data sources** — execute arbitrary shell commands. Non-deterministic by nature: the command may return different results between plan and apply, or between runs. Flag as **MEDIUM** with recommendation to replace with native resources or `terraform_data` where possible.
- **`http` data sources** — fetch remote URLs at plan time. Response may change between plan and apply. Flag as **MEDIUM** if the URL targets a mutable endpoint (API, dynamic content). **LOW** if it targets a static resource (schema file, version manifest).
- **Mutable infrastructure data sources** — data sources that read live infrastructure state (e.g., `data.google_compute_instance`, `data.google_container_cluster`, `data.aws_instance`) where the same resource is also managed by Terraform in the same or a different state. The read value may drift between plan and apply if another process modifies the resource. Flag as **LOW** with a note about plan/apply consistency risk.
- **Missing dependency on created resources** — data sources that query infrastructure created in the same apply but lack an explicit `depends_on`. Terraform may evaluate the data source before the resource exists, causing a failure on first apply. Flag as **MEDIUM**.

### 5j. Workspace collision detection (NEW)
Detect whether the codebase uses Terraform workspaces and assess resource naming safety:
- **Detection**: scan for `terraform.workspace` references, `workspace`-related expressions, or multiple environment-named `.tfvars` files alongside workspace selection in CI/CD configs
- If workspaces are in use:
  - Check that resource names interpolate `terraform.workspace` or `var.environment` (or equivalent). Resources with static names (e.g., `name = "my-vpc"`) will collide when the same config is applied in multiple workspaces. Flag as **HIGH**.
  - Check for `terraform.workspace` used in `count` or `for_each` conditions (e.g., `count = terraform.workspace == "prod" ? 1 : 0`). This is an anti-pattern — workspace-conditional resources make the codebase harder to reason about and test. Flag as **MEDIUM** with recommendation to use separate root modules or variable-driven feature flags instead.
  - Check that backend configuration uses workspace-aware key/prefix patterns (e.g., `prefix = "env:"`). A backend without workspace prefix stores all workspace states in the same key. Flag as **HIGH**.
- If workspaces are NOT in use, skip this check (report as **INFO**: "No workspace usage detected — environment isolation is directory-based").

---

## Step 6: Analyze — Simplicity

### 6a. Over-engineering
- Unnecessary abstractions — modules wrapping a single resource with no added logic
- Complex `dynamic` blocks where a static block would be clearer
- Nested ternaries or deeply chained `coalesce`/`try` expressions
- Feature flags or toggles for things that are always on or always off in practice

### 6b. Unnecessary complexity
- `count` used for conditional creation where a simple `for_each` with an empty map is cleaner → **ROB-COUNT-001** (detection pass flags `count = <expr> ? 1 : 0` patterns automatically)
- `templatefile` used where `jsonencode`/`yamlencode` would be simpler
- Data sources used to look up values that could be passed as variables
- Provisioners (`local-exec`, `remote-exec`) used where native resources exist

### 6c. Dead code
- Commented-out resources or blocks
- Variables with defaults that are always overridden in every `.tfvars`
- Outputs that no other module or external system consumes
- Unused `locals` values
- Configuration keys stored in Vault/KV/ConfigMaps that no application code reads (cross-reference with app source if accessible)

---

## Step 7: Analyze — Operational Readiness (NEW)

### 7a. Tagging and labeling → OPS-GCP-LABELS-001
- Are all GCP resources tagged with at least: `environment`, `managed_by`, `project`? → **OPS-GCP-LABELS-001** (detection pass flags `google_compute_instance`, `google_storage_bucket`, `google_sql_database_instance`, `google_container_cluster`, `google_compute_disk`, `google_pubsub_topic`, `google_cloud_run_service`, and `google_bigquery_dataset` resources missing their respective labels argument)
- Is there a consistent `common_labels` local used across all modules?
- Are K8s resources labeled with `app.kubernetes.io/*` labels consistently?
- Are resources missing labels that would be needed for cost attribution or monitoring?

### 7b. Monitoring and alerting
- Are there any monitoring resources defined? (alert policies, uptime checks, log-based metrics)
- Are GKE clusters configured with `monitoring_service`?
- Are there PodDisruptionBudgets for critical deployments?
- Are there any `google_monitoring_*` resources?

### 7c. Backup and disaster recovery
- Is the state backend bucket versioned? (Enables state rollback)
- Are databases or storage buckets backed up? (lifecycle rules, snapshots)
- Is there a documented recovery procedure for key infrastructure? (Cross-reference CLAUDE.md)

### 7d. Cost signals
- Oversized machine types for workload (e.g., `n2-standard-16` for a 256Mi-memory pod)
- Always-on resources that could use preemptible/spot instances
- `pd-ssd` disks where `pd-balanced` would suffice
- Missing committed use discounts for stable workloads (INFO only — note if applicable)

### 7e. Cost-risk controls → COST-GCP-RISK-001
The detection pass flags expensive resources that lack explicit cost controls:
- **Spanner** without `processing_units` — defaults may be expensive and unclear
- **GKE** without `cluster_autoscaling.resource_limits` — unbounded scale-up
- **Cloud SQL** without `settings.disk_autoresize_limit` — unbounded disk growth
- **Compute** without `scheduling` block — always-on by default (consider preemptible for dev)

These are not security issues but can cause significant bill surprises. Tagged as MEDIUM urgency.

---

## Step 8: Analyze — CI/CD and Testing Maturity (NEW)

This step assesses whether automated guardrails exist around the Terraform codebase. The ABSENCE of these is itself a finding.

### 8a. CI/CD pipeline
Check for the existence of:
- `.github/workflows/` (GitHub Actions)
- `.gitlab-ci.yml` (GitLab CI)
- `Jenkinsfile`
- `buildspec.yml` (AWS CodeBuild)
- `.circleci/config.yml`

If NONE exist, flag as **HIGH**: "No CI/CD pipeline detected. Terraform changes are applied manually without automated plan/validate/apply gates."

If a pipeline exists, check whether it runs:
- `terraform validate`
- `terraform plan` (and stores the plan artifact)
- `terraform fmt -check`
- Any security scanner (tfsec, trivy, checkov, terrascan)

### 8b. Pre-commit hooks
Check for `.pre-commit-config.yaml`. If absent, flag as **MEDIUM**: "No pre-commit framework. Consider adding hooks for terraform fmt, tflint, detect-secrets."

### 8c. Linting
Check for `.tflint.hcl`. If absent, flag as **MEDIUM**: "No TFLint configuration. TFLint catches provider-specific errors (invalid instance types, deprecated arguments) that Terraform validate misses."

### 8d. Policy-as-code
Check for:
- `*.sentinel` files (Sentinel policies)
- `policy/` or `policies/` directories with `*.rego` files (OPA/Conftest)
- `.conftest` directory or `conftest.toml`

If NONE exist, flag as **MEDIUM**: "No policy-as-code enforcement. Consider OPA/Conftest for organizational policies (e.g., no public-facing LoadBalancers, mandatory labels, encryption requirements)."

### 8e. Terraform test coverage → CI-TEST-001
Check for:
- `*.tftest.hcl` files (native Terraform test framework, 1.6+)
- `*_test.go` files near modules (Terratest)
- `tests/` directories

If NONE exist at the repo level, flag as **MEDIUM**: "No Terraform tests. Consider `terraform test` (native) for module contract testing, or Terratest for integration tests."

**Per-module coverage** is now checked by the detection pass via `CI-TEST-001` (`module_missing_tests` pattern kind). For each module directory that contains `.tf` files but no `.tftest.hcl` files (in either the module root or a `tests/` subdirectory), `detect.py` emits a `CI-TEST-001` finding. This catches modules that were added without any test coverage.

---

## Step 9: Analyze — Cross-Module Contracts (NEW)

### 9a. Output-to-input type matching
For each module call in scenario files:
- Verify that the types of values passed to module inputs match the declared variable types
- Check for outputs consumed by `module.X.output_name` that don't exist in module X's `outputs.tf`
- Flag outputs that are declared but never consumed by any caller (dead outputs)

### 9a.i Output stability
Module outputs that downstream modules or `terraform_remote_state` consumers depend on are an **API contract**. Flag changes that would break consumers:
- Outputs whose `value` expression depends on `count` / `for_each` of a conditional resource (output may flip from a value to `null` between runs)
- Outputs that returned a primitive in a previous report and now return an object (or vice versa) — read prior reports to detect this
- Module outputs renamed without a corresponding `moved` block strategy (Terraform has no `moved` for outputs — renames are breaking changes)
- Outputs missing `description` AND consumed by a `terraform_remote_state` data source — undocumented cross-state contracts are the highest-leverage doc gap in any multi-state codebase. Flag as **MEDIUM**.

### 9b. Orphaned modules
List any module directories under `tf/modules/` that are never referenced by any `source =` in any scenario. These are candidates for removal.

### 9c. Variable pass-through depth
Identify variables that pass through 3+ layers without transformation:
```
scenario/variables.tf:gcp_project_id → module.foo(gcp_project_id) → module.bar(project_id)
```
Flag chains of 3+ as **LOW** — consider whether the intermediate module adds value or just proxies the variable.

### 9d. Dependency graph bottlenecks (NEW)
Identify resources with high fan-out that represent single points of failure for replacements:
- Parse all `.tf` files for resource attribute references (e.g., `google_compute_network.main.id`, `module.vpc.network_id`) and explicit `depends_on` entries
- Build a dependency map: for each resource, count how many other resources reference it (directly or via module outputs)
- Flag resources referenced by **10+ other resources** as dependency chokepoints — tag with **INFO** and note:
  - "Replacing or tainting this resource will trigger cascading re-creation of N dependents"
  - Include the blast radius: `single-resource` if dependents are all in the same module, `module` if cross-module, `infrastructure-wide` if cross-scenario
- Common chokepoints to watch for: VPCs/networks, root CAs, GKE clusters, state buckets, service accounts, Vault auth backends
- If any chokepoint lacks `lifecycle { prevent_destroy = true }`, escalate to **MEDIUM** — an accidental destroy cascades to all dependents

### 9e. Backend configuration consistency → ROB-BACKEND-001
The detection pass flags inconsistent backend types via `ROB-BACKEND-001` (`backend_inconsistency` pattern kind). When multiple `backend` blocks exist across the codebase with different types (e.g., `gcs` vs `s3`), all but the first are flagged. The judgement pass should additionally check:
- Extract the `backend` block from each scenario's `terraform` block (typically in `versions.tf` or `backend.tf`)
- Check for consistency:
  - Same backend type across all scenarios (e.g., all use `gcs`, not a mix of `gcs` and `s3`)
  - Same bucket/container name (state for one project should live in one bucket)
  - Distinct prefix/key per scenario (to avoid state collisions)
  - Consistent encryption settings (all encrypted or none — mixed is a red flag)
- Flag scenarios with **no backend configuration at all** as **HIGH** — they use local state, which is not shared, not locked, and not recoverable
- Flag inconsistent backend types as **HIGH** — makes unified state management and DR impossible
- Flag inconsistent encryption settings as **MEDIUM** — some state files are protected, others are not
- Flag missing prefix/key differentiation as **CRITICAL** — two scenarios writing to the same state key will corrupt each other

---

## Step 10: Analyze — Stack-Specific Checks (NEW)

Apply these checks based on which providers and resources are detected in the codebase.

### 10a. Vault-specific (if `vault_*` resources present)
- Missing `vault_audit` resource — is Vault auditing enabled?
- Vault policies using wildcard paths (`path "secret/*"`) — flag for review
- Vault lease/token TTL alignment — do `token_ttl`, `token_max_ttl`, secret engine `default_lease_ttl_seconds`, and `max_lease_ttl_seconds` values form a coherent chain?
- Vault auth backend config completeness — `vault write auth/kubernetes/config` replaces ALL fields. Is the Terraform resource setting `kubernetes_host`, `kubernetes_ca_cert`, `token_reviewer_jwt`, AND `issuer`?
- Version alignment: vault-agent version (in K8s container images) vs Vault server version vs Vault provider version. Flag mismatches.

### 10b. Consul-specific (if `consul_*` or `helm_release.consul` present)
- ACL default policy — should be `deny` in production
- TLS enforcement — is `global.tls.httpsOnly = true`?
- Service intentions — are deny intentions defined for services that shouldn't communicate?
- gossip encryption key management

### 10c. GKE-specific (if `google_container_cluster` present)
- `deletion_protection = false` on production clusters (flag as **HIGH**) → CIS 8.5.x
- `enable_legacy_abac = true` (flag as **CRITICAL** — must be false) → CIS 8.5.1
- Missing Shielded Nodes (`enable_secure_boot`, `enable_integrity_monitoring`) → CIS 8.4.2
- Network Policy not enabled (`network_policy.enabled = false`) → CIS 8.4.1
- Workload Identity not enabled → CIS 8.5.2
- Private nodes not enabled (`enable_private_nodes = false`) → CIS 8.5.3
- Missing `master_authorized_networks_config` (API server open to all) → CIS 8.5.4
- Application-layer Secrets Encryption not enabled → CIS 8.5.5
- Node image not Container-Optimized OS → CIS 8.6.1
- Node pool auto-upgrade disabled → CIS 8.6.2
- Node pool auto-repair disabled → CIS 8.6.3
- `logging_service` not set to `"logging.googleapis.com/kubernetes"` → CIS 8.7.1
- `monitoring_service` not set to `"monitoring.googleapis.com/kubernetes"` → CIS 8.7.2
- Basic auth still enabled (`master_auth.username` non-empty) → CIS 8.8.1
- Client certificates still issued (`client_certificate_config.issue_client_certificate = true`) → CIS 8.8.2
- GKE release channel not set (no auto-upgrade path)

### 10d. Cloud SQL-specific (if `google_sql_database_instance` present)
- Public IP enabled (`settings.ip_configuration.ipv4_enabled = true`) → CIS 6.1.1
- `require_ssl = false` → CIS 6.1.2
- Authorized networks include `0.0.0.0/0` → CIS 6.1.3
- Postgres `log_checkpoints` flag off → CIS 6.2.1
- SQL Server `external scripts enabled` flag on → CIS 6.3.1
- Backups not configured → **STK-GCP-CLOUDSQL-001** | CIS 6.4
- HA not enabled (`availability_type != "REGIONAL"` for production) → CIS 6.5
- `deletion_protection = false` → CIS 6.6
- Missing `point_in_time_recovery_enabled` for Postgres / MySQL

### 10e. BigQuery-specific (if `google_bigquery_dataset` / `google_bigquery_table` present)
- Public access via `allUsers` / `allAuthenticatedUsers` in dataset access blocks → **SEC-GCP-IAM-002** | CIS 7.1
- Tables/datasets without CMEK → CIS 7.2, 7.3

### 10f. Helm-specific (if `helm_release` resources present)
- `wait = false` on releases where ordering matters
- Missing `timeout` on CRD-installing charts
- `create_namespace = true` when Terraform should manage the namespace
- Unpinned chart versions or `version = "latest"`

---

## Step 11: CLAUDE.md Convention Verification (NEW)

If CLAUDE.md exists (read in Step 0e), verify that the Terraform code implements the rules it documents:

- For each quantitative claim (e.g., "PKI TTLs: root 10yr, intermediate 5yr, leaf 72h"), verify the actual values in the `.tf` files match.
- For each "no default" rule (e.g., "`vault_users` must be set explicitly"), verify the variable has no `default` value.
- For each naming convention (e.g., `{environment}-{component}-{resource}`), spot-check resource names.
- For each security rule (e.g., "IAM least-privilege"), verify the IAM bindings match the documented roles.

Flag mismatches between CLAUDE.md and code as **HIGH** — documentation-code divergence erodes trust in both.

---

## Step 12: Cost Estimation

Cost informs urgency: a $5/month bucket missing `prevent_destroy` is LOW; a $5,000/month Spanner instance missing `prevent_destroy` is HIGH. Catalogue entries with `escalation: estimated_monthly_cost_usd > N` rules use this step's output.

### 12a. Prefer the `tf-cost` skill when available

The repo's `tf-cost` skill (at `~/.claude/skills/tf-cost/`) wraps `infracost`
with provider-specific knowledge — HCP tier pricing, GKE machine-type
parity checks, region cost bands — that bare `infracost` does not have.
**Call `tf-cost` first** so the dollar figures and per-resource breakdown
in this report come from the same source as a stand-alone cost run:

```bash
if [ -d ~/.claude/skills/tf-cost ]; then
  # `tf-cost` is itself a skill — invoke via the Skill tool, not bash —
  # and consume its JSON breakdown from /tmp/tf-cost-breakdown.json.
  Skill tf-cost args:"path:<TARGET_DIR> action:breakdown format:json"
fi
```

If `tf-cost` is unavailable, fall back to direct infracost:

```bash
if command -v infracost >/dev/null 2>&1; then
  infracost breakdown --path <TARGET_DIR> --format json > /tmp/tf-analyze-infracost.json
fi
```

Parse the JSON and produce a cost table grouped by resource. Use these
dollar figures directly in the report's Cost Snapshot section.

**Cost-driven escalation.** When `tf-cost` provides a *plan-time delta*
(`tf-cost action:diff`) the values feed two escalation paths:

1. **Per-finding escalation.** Catalogue entries with
   `escalation: estimated_monthly_cost_usd > N` rules consume this
   step's per-resource cost figure. A `prevent_destroy`-missing finding
   on a $5/month bucket stays LOW; the same finding on a $5,000/month
   Spanner instance escalates to HIGH.
2. **Cross-cutting `COST-DELTA-001`.** If the plan-time monthly delta
   exceeds the configured threshold (default $500/month, configurable
   via `tf-cost`'s budget gate), emit `COST-DELTA-001` as a synthetic
   finding in the report's Executive Summary and tag it HIGH. This
   surfaces the cost change as a first-class signal even when no
   individual finding fires — useful for catching "we accidentally
   left a 100-node GKE pool in the plan" mistakes that pass every
   other check.

If `tf-cost` is not installed, skip the escalation paths above and treat
all cost-driven findings at their `default_urgency`.

### 12b. Fall back to size classes when infracost is absent

When infracost is not installed, do **not** invent dollar figures from a price table — they decay quickly and are systematically wrong (committed-use discounts, free tiers, data egress dominate compute on real bills). Instead, classify each billable resource into a relative size class:

| Class | Roughly | Examples |
|---|---|---|
| **XS** | <$10/mo | Cloud Scheduler job, single small bucket, Pub/Sub topic with low volume |
| **S** | $10–100/mo | e2-medium, db-f1-micro, Cloud Run with light traffic |
| **M** | $100–500/mo | n2-standard-4, db-n1-standard-1, single GKE Standard cluster |
| **L** | $500–2,000/mo | Multi-node GKE Standard, Cloud SQL HA, 100-PU Spanner |
| **XL** | >$2,000/mo | Multi-node GKE with autoscaler ceiling, multi-region Spanner, large BigQuery slot reservation |

Class is derived deterministically from `machine_type` family + `node_count` + `tier` + storage size — no per-unit pricing required. The Cost Snapshot table reports class and ranges, not exact figures:

```text
| Resource                                       | Sizing               | Class | ~$/month |
|------------------------------------------------|----------------------|-------|----------|
| google_spanner_instance.graph                  | 100 PU regional      | M     | $100–500 |
| google_storage_bucket.rag_docs                 | 10 GB standard       | XS    | <$10     |
| google_container_node_pool.workers (×3 n2-4)   | n2-standard-4        | M     | $100–500 |
```

### 12c. Cost-driven escalation

Walk every finding from the detection pass. For each one whose catalogue entry has an `escalation` rule keyed on cost class or dollar threshold, apply the escalation:
- `ROB-GCP-LIFECYCLE-001` on an XS bucket → urgency stays HIGH (per default).
- `ROB-GCP-LIFECYCLE-001` on an XL Spanner instance → urgency stays HIGH but is flagged for action plan top-3.

If `mode:plan`, prefer the actual `for_each` / `count` expansion from the plan JSON over the static count (a `for_each` over a list of 8 entries means 8× the unit cost, not 1×).

End the cost section with: _"Estimates are directional. Install `infracost` for line-item accuracy, or use the official cloud pricing calculator before procurement decisions."_

---

## Step 13: Plan-Time Analysis (mode:plan only)

**Only run this step if `mode:plan` was specified.** This requires credentials and remote state access. Also run `terraform refresh` first if you suspect external drift — without refresh, "drift from state" detection only catches drift that has been observed in a prior plan/apply.

```bash
terraform -chdir=<TARGET_DIR> refresh
```

```bash
terraform -chdir=<TARGET_DIR> init
terraform -chdir=<TARGET_DIR> plan -out=tfplan -var-file=<ENV>.tfvars 2>&1
terraform show -json tfplan > /tmp/tfplan.json
```

Analyze the plan JSON for:
- **Destroy-and-recreate operations** — resources that will be destroyed due to immutable field changes. Flag each with the reason (name change, provider-forced replacement, etc.).
- **Drift from state** — resources where the plan shows changes not caused by code modifications (external mutation).
- **Computed values** — values computed at plan time that might be dangerous (e.g., a CIDR derived from a data source that resolves to `0.0.0.0/0`).
- **Resource counts** — actual `for_each` / `count` expansion. How many real resources does the plan manage?
- **No-op plan** — if `terraform plan` shows "No changes", report that as a positive finding.

### State performance signals (plan mode only)
Assess whether the state size may cause operational issues:
- Count total managed resources from the plan JSON (`resource_changes` array length, excluding data sources)
- **>500 resources** → **MEDIUM**: "Plans will be slow (expect 2-5 min). Consider splitting state by domain (networking, compute, platform services) using separate root modules with `terraform_remote_state` data sources for cross-references."
- **>1000 resources** → **HIGH**: "State is large enough to cause plan timeouts, lock contention, and blast radius concerns. State splitting is strongly recommended."
- Group resources by module path from the plan JSON. Flag any single module with **>50 resources** as **MEDIUM**: "Module `module.X` manages N resources — candidate for decomposition."
- Record plan execution time (wall clock from `terraform plan` start to finish). Flag if **>3 minutes** as **MEDIUM** with the resource count for context.
- Report the total resource count in the executive summary regardless of threshold, as a baseline metric.

---

## Step 14: Recommendation Verification

After collecting all findings but **before** writing the report, verify every recommendation that names a specific resource type, role name, OAuth scope, or argument. Recommendations that the agent invented from a general principle are the single largest source of factually wrong advice in this skill's history.

**Cheap path first:** check Appendix A. If a recommendation proposes a resource type listed in the IAM compatibility matrix (or any other matrix in this document), the matrix is authoritative and no validate run is needed. The matrix exists *because* it is faster than running `terraform validate` for every candidate.

**Expensive path second:** for recommendations not covered by the matrix, use the **sentinel tempdir** created in Step 1c. Do NOT create a new tempdir per recommendation — that costs ~30s per `init` and dominates runtime in any non-trivial run.

### 14a. Provider-resource existence check (sentinel tempdir)

The sentinel tempdir at `$TF_ANALYZE_SENTINEL` already has providers downloaded. To verify a proposed resource:

```bash
# Append the proposed block as a new file in the sentinel tempdir
cat > "$TF_ANALYZE_SENTINEL/proposed_${REC_ID}.tf" <<'EOF'
# ...the recommended block, with placeholder values for any required fields...
EOF
terraform -chdir="$TF_ANALYZE_SENTINEL" validate 2>&1
```

`terraform validate` runs in <2s once init has been done. Batch all recommendation files into the same sentinel and run validate **once at the end** of Step 14a. The validate output names the offending file for any rejected recommendation.

If validate rejects a type, **demote the recommendation** to "research note" status and add an explicit warning in the report: "Initial recommendation invalid against `<provider>` `<version>` — see Appendix A for the IAM compatibility matrix." Then re-derive a working recommendation (e.g., fall back to project-level + IAM Conditions) and re-run validate on the rewrite.

After Step 14 completes, clear the proposed_*.tf files from the sentinel:

```bash
rm -f "$TF_ANALYZE_SENTINEL"/proposed_*.tf
```

### 14b. Role and scope existence check

For every recommendation that names an IAM role (`roles/foo.bar`) or OAuth scope (`https://www.googleapis.com/auth/X`):

- Roles: cross-reference against the GCP/AWS/Azure managed-roles list. If the role is not in the well-known list and looks suspicious, **never invent a role name** — instead recommend "audit current role and remove unused permissions" and let the operator pick the replacement.
- OAuth scopes: only `https://www.googleapis.com/auth/cloud-platform` and the documented narrow scopes from the [Google OAuth 2.0 Scopes reference](https://developers.google.com/identity/protocols/oauth2/scopes) are valid. Do not invent narrower scopes for APIs that don't publish one. The Workflows Executions API in particular only supports `cloud-platform`. When in doubt, recommend the IAM-layer mitigation, not the OAuth-layer one.

### 14c. Argument existence check

For every recommendation that names a specific resource argument (`force_destroy`, `deletion_protection`, `lifecycle { prevent_destroy = true }`, `public_access_prevention`, etc.), verify the argument is supported on the target resource type in the locked provider version. Use the sentinel tempdir from Step 14a.

### 14d. Recommendation status flags

Every recommendation in the final report MUST carry one of these status flags:

| Flag | Meaning |
|---|---|
| **VERIFIED** | The recommended fix was sketched in a tempdir and `terraform validate` accepted it. Safe to apply directly. |
| **NEEDS-REVIEW** | The recommendation is qualitative ("audit IAM roles", "consider CMEK") and cannot be mechanically verified. Operator judgment required. |
| **SPECULATIVE** | The recommendation could not be verified (no provider lock file, validate failed for an unrelated reason, recommendation depends on context outside the codebase). Operator must verify before applying. |

A recommendation that initially failed verification and was rewritten should be tagged **VERIFIED** for the rewritten version, with a one-line note about the original attempt: "Initial proposal `google_workflows_workflow_iam_member` invalid in google 6.50; revised to project-level binding."

---

## Step 15: Verification Mode (verify-fixed)

If `mode:verify-fixed` was specified, **do not perform a full re-scan**. Catalogue IDs make this mode reliable across runs — the join key is `(file, catalogue_id)`, not the prose title.

1. Find the most recent prior report:
   ```bash
   ls -t reports/tf-analysis-*.md 2>/dev/null | head -1
   ```
2. Parse the report's findings table to extract every finding ID, file path, line number, and a one-line description of what to look for.
3. For each open finding (i.e. not in a "Resolved" delta section):
   - Read the named file at the named line range.
   - Check whether the specific anti-pattern still exists. Use targeted Grep where possible — do not re-read the whole file unless necessary.
   - Classify the finding's current state:

| State | Meaning |
|---|---|
| **STILL-PRESENT** | The exact issue is unchanged. |
| **RESOLVED** | The issue is gone (file edited, resource removed, argument added). |
| **MOVED** | The issue moved to a different file/line — provide the new location. |
| **AMBIGUOUS** | The code around the original location has changed in a way that makes the original finding non-comparable. Operator should review. |
| **STALE-LOCATION** | The original file or resource no longer exists. The finding may have been resolved by deletion, or the report itself may be out of date. |

4. Write a verification report to `reports/tf-analysis-verify-YYYY-MM-DD.md` with:
   - The path of the prior report being verified.
   - A summary table: N still-present, N resolved, N moved, N ambiguous, N stale-location.
   - A per-finding section with the new state, evidence (file:line excerpt), and recommended action.
5. Do NOT introduce new findings in verify-fixed mode. If the agent notices a new issue while reading, log it as a note at the bottom of the verification report and recommend running a full `mode:static` scan.

Verify-fixed mode is significantly cheaper than a full scan (~10× fewer file reads, no fresh discovery, no full security pass) and gives reproducible closure tracking.

---

## Step 16: Generate Report

Generate the report filename by embedding the current datetime (date + time) so multiple runs on the same day are uniquely named and sortable:

```bash
REPORT_TS=$(date +%Y-%m-%d-%H%M%S)
REPORT_FILE="reports/tf-analysis-${REPORT_TS}.md"
mkdir -p reports
```

Write the report to `${REPORT_FILE}` (create `reports/` if needed).

### Delta comparison

Before writing, check for previous reports:
```bash
ls -t reports/tf-analysis-*.md 2>/dev/null | head -1
```

If a previous report exists, read it and compute a delta:
- Findings resolved (present in previous, absent now)
- New findings (absent in previous, present now)
- Unchanged findings

Include the delta in the report header after the executive summary.

### Risk Score

The score and letter grade are **emitted by `detect.py` directly** as part of every `--format json`, `--format text`, and `--format html` output. The agent should quote the engine's number, never recompute it.

Single source of truth: `_RISK_WEIGHTS` and `_GRADE_TIERS` in `scripts/detect.py`. The current weights are:

```text
score = max(0, 100 - (15 * CRITICAL + 7 * HIGH + 3 * MEDIUM + 1 * LOW))
```

INFO findings do not affect the score (weight 0). Suppressed findings (both `# tf-analyze:ignore` / `.tf-analyze-ignore.yaml` and `--baseline` matches) count at half weight — they have been acknowledged but the underlying risk still exists. The grade tiers:

| Grade | Score range |
|-------|-------------|
| **A** | 90 – 100 |
| **B** | 75 – 89  |
| **B-** | 65 – 74 |
| **C** | 50 – 64  |
| **D** | 30 – 49  |
| **F** | 0 – 29   |

Worked examples (verified by `tests/test_output_formats.py::TestComputeSummary`):
- 0 CRITICAL, 0 HIGH, 4 MEDIUM, 6 LOW → 100 − (0 + 0 + 12 + 6) = **82 (B)**
- 0 CRITICAL, 4 HIGH, 11 MEDIUM, 6 LOW → 100 − (0 + 28 + 33 + 6) = **33 (D)**
- 0 CRITICAL, 0 HIGH, 0 MEDIUM, 0 LOW → **100 (A)**

The formula intentionally penalises HIGH (7) more than 2× MEDIUM (6) to reflect the reality that one HIGH usually causes more pain than two MEDIUMs.

**Where the score appears in the engine output:**

| Format       | Where                                                         |
|--------------|---------------------------------------------------------------|
| `text`       | First line: `# tf-analyze: 82 (B) · 0 CRITICAL · 0 HIGH · …` |
| `json`       | Top-level `summary` key, always present                       |
| `html`       | Colour-banded banner above the findings panel                 |
| `sarif`      | Not emitted (SARIF v2.1 has no canonical aggregate slot)      |

**Stability:** the `summary` JSON block is part of the public CLI contract. Keys (`scoring_version`, `score`, `grade`, `counts`, `suppressed_count`, `formula`) are stable; weight changes bump `_SCORING_VERSION` (currently `1`).

**Don't add `--exit-on-grade`.** `--fail-on HIGH` already exists and gates on the *kind* of finding, not on a derived number. A grade gate invites suppression-to-bump-score gaming; mature scanners (tfsec, checkov) deliberately avoid it. If the agent's qualitative read disagrees with the score, fix the underlying urgency calibration in the catalogue rather than overriding the score in the report.

### 16e. Adversarial Scenarios

For every HIGH and CRITICAL finding in the report, append an **Adversarial Scenarios** section.
Each row names the specific resource, the attack technique an adversary would use, the blast
radius, and (where applicable) a confirmed public breach that used the same vector.

Use the pre-written narratives in `_ATTACK_NARRATIVES` inside `scripts/detect.py` as the source
for the 15 covered rule IDs. For any HIGH/CRITICAL finding whose rule ID is not in that dict,
generate a 2-3 sentence scenario following the same pattern: technique → blast radius → fix.

```markdown
## Adversarial Scenarios

| Finding | Resource | Scenario |
|---|---|---|
| SEC-AWS-SSRF-001 | `aws_instance.web` | SSRF → IMDSv1 → unauthenticated credential retrieval → S3 exfiltration (Capital One 2019 pattern). IMDSv2 breaks this chain — the attacker's forged request cannot complete the required PUT handshake. |
| SEC-AWS-IAM-001 | `aws_iam_policy.broad` | Wildcard Resource grants declared actions across every resource in the account; any credential theft or SSRF hitting this role yields account-wide blast radius. Narrow the Resource ARN to specific bucket/table/secret ARNs. |
| SEC-AWS-KMS-001 | `aws_kms_key.data_key` | Disabled rotation means key-material compromise — via insider threat or account takeover — is permanent. CIS AWS 2.8 and PCI-DSS 3.6.4 both require rotation; enable `enable_key_rotation = true`. |
```

Rules:
- Reference only confirmed public incidents: Capital One 2019, SolarWinds 2020, Tesla 2020
  Kubernetes, Samsung 2022, Twitch 2021, Verizon 2017, Accenture 2017. Do not speculate.
- Keep each scenario ≤ 4 sentences.
- Order CRITICAL before HIGH, then by blast radius (infrastructure-wide first).
- If `--attack-graph` was run and `critical_path` is non-empty, add a **Critical Attack Path**
  paragraph *above* the table describing the end-to-end chain in narrative prose: who the
  attacker is, what resource they compromise first, how they pivot to the crown jewel, and what
  data or capability they gain.

### 16f. New features to use in reports

The following CLI features are available and should be recommended or invoked where relevant:

**`--show-fixes`** — When a catalogue entry has a `fix_hcl` field, the HTML and text reports include the actual corrected HCL block. In Claude skill mode: for every finding you recommend fixing, include the corrected resource block as a fenced HCL snippet under the recommendation.

**`--gen-tests OUTDIR`** — Generates native `terraform test` (`.tftest.hcl`) assertion files for each finding with a `test_template`. Recommend this to teams that use Terraform ≥ 1.6 so fixes become permanent regression guards. In Claude skill mode: after resolving a finding, offer to write the equivalent `tftest.hcl` assertion.

**`--attack-graph --format html`** — Adds three tabs: Findings, Attack Graph (interactive SVG), and Executive View (findings organised into Entry Points / Lateral Movement / Crown Jewels at Risk / Blind Spots). The Executive View is ideal for sharing with non-technical stakeholders who need to understand risk without reading rule IDs. In Claude skill mode: always produce the Adversarial Scenarios table (§16e) and, when a critical path exists, prepend the "Critical Attack Path" paragraph.

**`--mode fleet --target dir1 --target dir2`** — Scans multiple repos and cross-correlates findings. Findings appearing in more than one repo are tagged FLEET-WIDE. Use when the user has asked to audit multiple workspaces or an entire organisation's Terraform. In Claude skill mode: if the user provides multiple repo paths, note that a fleet scan would identify shared misconfigurations.

**`--mode trend --lookback 30`** — Walks git history to show how the risk profile has changed over the last 30 days. Use when the user asks "is our security posture improving?" or requests a risk trend report. In Claude skill mode: include the trend table in the Appendix and note whether the net finding count is increasing or decreasing.

**Reachability-aware urgency** — When `--attack-graph` is active, findings on critical-path resources show a `CRITICAL-PATH` badge and have been promoted one urgency tier. In Claude skill mode: call these out explicitly in the Executive Summary — they represent the highest-priority fixes because they are on a confirmed attack path.

**INT-INTENT-* rules** — New rule family detecting intent-implementation gaps: variables signalling security intent that default to false/null/0, prod-tagged resources with `deletion_protection=false` or `force_destroy=true`. Include these findings in the Executive Summary when found — they represent developer intent that was never enforced.

**MOD-SUPPLY-* rules** — New rule family for module supply-chain risks: mutable git refs (`?ref=main`), raw git sources, registry modules without `version`. Flag these in the Action Plan under "Supply Chain Hygiene."

### Report structure

```markdown
# Terraform Code Analysis Report

**Date:** YYYY-MM-DD
**Scope:** <path analyzed>
**Files scanned:** N .tf files across M modules/scenarios
**Focus:** <all | specific area>
**Mode:** <static | plan>
**Health Grade:** <A-F> (<score>/100)

---

## Executive Summary

<2-3 sentence overview of the overall health of the Terraform codebase, highlighting the most important findings>

**Strengths:** <one sentence calling out 1–3 patterns the codebase does well — e.g., state backend uses CMEK + versioning; all stateful resources carry prevent_destroy; CI runs tfsec + fmt + validate on every PR>

**Finding counts by urgency:**

| Urgency | Count |
|---------|-------|
| CRITICAL | N |
| HIGH | N |
| MEDIUM | N |
| LOW | N |
| INFO | N |

### Delta (vs previous report YYYY-MM-DD)

- **Resolved:** N findings (list IDs)
- **New:** N findings (list IDs)
- **Unchanged:** N findings

### Finding density by file

Surface the worst-offender files so refactor effort can be targeted. Sort descending by total findings, then by max urgency. Include the top 10 files (or all files with ≥2 findings, whichever is shorter). Files with zero findings are omitted.

| File | Lines | CRITICAL | HIGH | MEDIUM | LOW | Total | Density* |
|------|-------|----------|------|--------|-----|-------|----------|
| terraform/modules/x/iam.tf | 142 | 0 | 2 | 3 | 1 | 6 | 4.2 |
| terraform/modules/x/storage.tf | 89 | 0 | 1 | 2 | 0 | 3 | 3.4 |
| ... | | | | | | | |

*Density = (findings × 100) / lines. Use density to distinguish "small file with concentrated problems" from "large file with scattered issues" — the former is usually a higher-leverage refactor target.

---

## 1. Security Posture

### CRITICAL

- **[SEC-GCP-IAM-002#1] Public bucket binding** — terraform/modules/foo/iam.tf:42 | Blast: infrastructure-wide | CIS: 5.1 | Effort: Small | Status: VERIFIED
  Description: `google_storage_bucket_iam_member` grants `roles/storage.objectViewer` to `allUsers`, exposing every object to anonymous reads.
  Recommendation: Remove the binding; add a signed-URL pattern if external read access is required.
  Verification: `gcloud storage buckets get-iam-policy gs://<bucket> --format='value(bindings)' | grep allUsers` returns nothing.

### HIGH
...

(Continue for all urgency levels with findings. Omit empty levels per the auto-collapse rule.)

---

## 2. DRY and Code Reuse
(Same structure: findings grouped by urgency within the section)

---

## 3. Style and Conventions
(Same structure)

---

## 4. Robustness
(Same structure)

---

## 5. Simplicity
(Same structure)

---

## 6. Operational Readiness
(Same structure)

---

## 7. CI/CD and Testing Maturity
(Same structure)

---

## 8. Cross-Module Contracts
(Same structure)

---

## 9. Stack-Specific Findings
(Same structure, subsections per stack: Vault, Consul, GKE, Helm)

---

## 10. CLAUDE.md Compliance
(Verification results: documented rules vs actual code)

---

## 11. Suppressed Findings
(List of suppressed findings with suppression reason and expiry date)

---

## 12. Positive Findings

<List things the codebase does well — patterns worth preserving, good security hygiene, clean module structure, etc.>

---

## 13. Recommended Action Plan

Group the top findings into urgency bands. Within each band sort by blast radius descending, then effort ascending (quick wins first). Show ALL CRITICAL findings; cap HIGH at 10, MEDIUM at 8, LOW at 5.

Use the effort definitions from Step 16 (Small ≤30 min / Medium ≤2 h / Large ≥half-day) in the Effort column. Each row should be immediately actionable — include a one-line description concrete enough for a developer to start without reading the full finding.

### CRITICAL — Fix Immediately

| # | Finding | Section | Effort | Blast Radius | Description |
|---|---------|---------|--------|--------------|-------------|
| 1 | SEC-GCP-IAM-002#1 | Security | Small | infrastructure-wide | Remove `allUsers` IAM binding on storage bucket |
| ... | | | | | |

_No CRITICAL findings_ — omit this sub-section if the band is empty.

### HIGH — Fix This Sprint

| # | Finding | Section | Effort | Blast Radius | Description |
|---|---------|---------|--------|--------------|-------------|
| 1 | ROB-GCP-LIFECYCLE-001#3 | Robustness | Small | module | Add `prevent_destroy` to stateful resource |
| ... | | | | | |

_No HIGH findings_ — omit this sub-section if the band is empty.

### MEDIUM — Plan to Address

| # | Finding | Section | Effort | Blast Radius | Description |
|---|---------|---------|--------|--------------|-------------|
| 1 | MOD-PIN-001#2 | DRY | Medium | module | Pin module source to a versioned ref |
| ... | | | | | |

_No MEDIUM findings_ — omit this sub-section if the band is empty.

### LOW — Address Opportunistically

| # | Finding | Section | Effort | Blast Radius | Description |
|---|---------|---------|--------|--------------|-------------|
| 1 | STYLE-DESC-001#4 | Style | Small | single-resource | Add description to variable block |
| ... | | | | | |

_No LOW findings_ — omit this sub-section if the band is empty.

### Related Findings

List clusters of findings that are related and should be addressed together:
- SEC-GCP-IAM-001#1 + ROB-GCP-LIFECYCLE-001#3: "project-level IAM AND missing prevent_destroy compound the blast radius"
- MOD-PIN-001#2 + SEC-PROVIDER-001#1: "unpinned modules and wide provider constraints together break reproducibility"
```

### SARIF output structure (when `format:sarif`)

The SARIF emitter (`scripts/detect.py --format sarif`) produces SARIF v2.1.0 JSON for upload to GitHub Code Scanning, Azure DevOps, or any SARIF-compatible viewer. Shape:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "tf-analyze",
        "informationUri": "https://github.com/anthropics/claude-code-skills/tree/main/tf-analyze",
        "rules": [{
          "id": "SEC-GCP-IAM-001",
          "name": "OverlyBroadIamRole",
          "shortDescription": { "text": "Overly broad IAM role" },
          "fullDescription": { "text": "<recommendation from catalogue>" },
          "helpUri": "https://github.com/anthropics/claude-code-skills/blob/main/tf-analyze/catalog/SEC-GCP-IAM-001.yaml",
          "help": { "markdown": "<recommendation>" },
          "properties": {
            "tags": ["security", "cis-1.6", "blast-radius:infrastructure-wide"],
            "security-severity": "7.5"
          }
        }]
      }
    },
    "results": [{
      "ruleId": "SEC-GCP-IAM-001",
      "level": "error",
      "message": { "text": "Project-level grant of roles/owner — narrow to resource scope." },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "tf/modules/iam/main.tf" },
          "region": { "startLine": 42 }
        },
        "logicalLocations": [
          { "name": "google_project_iam_member.broad_owner", "kind": "resource" }
        ]
      }],
      "partialFingerprints": {
        "tfAnalyze/v1": "<sha256(id|file|resource)>"
      }
    }]
  }]
}
```

**Severity mapping** (rule property `security-severity`, used by GitHub for PR-blocking thresholds):

| Catalogue urgency | SARIF `level` | `security-severity` |
|---|---|---|
| CRITICAL | error   | 9.5 |
| HIGH     | error   | 7.5 |
| MEDIUM   | warning | 5.0 |
| LOW      | note    | 3.0 |
| INFO     | note    | 1.0 |

**Rule tags** include `cis-<id>` for CIS-mapped controls, the catalogue domain (`security`, `robustness`, etc.), and `blast-radius:<value>`. GitHub Code Scanning surfaces these as filter facets.

**`partialFingerprints`** are sha256 of `<id>|<file>|<resource>`. They survive prose drift in the recommendation text but **not** file moves — a renamed file produces a RESOLVED + NEW pair on the next scan. For cross-rename stability, run `--compare` against a prior JSON report and diff at the `(id, resource)` level instead.

### Finding IDs

**All finding IDs come from the catalogue.** Each finding in the report MUST reference a catalogue entry by its stable `id` field (e.g., `SEC-GCP-IAM-001`, `ROB-GCP-LIFECYCLE-002`, `STK-GCP-CLOUDSQL-001`). Multiple instances of the same catalogue ID are disambiguated with `#N` suffix in source order: `SEC-GCP-IAM-001#1`, `SEC-GCP-IAM-001#2`, etc.

There is **no separate per-section prefix system** (`S-NNN`, `D-NNN`, etc. — removed). The catalogue is the only source of finding identity. If a finding does not yet have a catalogue entry, add the entry under `catalog/` first (see `catalog/README.md`), then reference it.

### CIS Benchmark Mapping

Where a security finding corresponds to a CIS GCP Foundation Benchmark v4.0 control, include the control ID. Reference table — only the controls below map to checks the skill already performs. If a finding doesn't fit one of these, leave the CIS column as `n/a` rather than inventing a control number.

**1.x — Identity and Access Management**
- 1.1 — Corporate login credentials used (no `gmail.com` accounts in IAM bindings)
- 1.4 — Service account user-managed keys rotated within 90 days
- 1.5 — Separation of duties on service accounts (no `roles/iam.serviceAccountUser` + `roles/iam.serviceAccountAdmin` on same identity)
- 1.6 — IAM users not assigned `roles/owner` at folder/org level
- 1.8 — Separation of duties for KMS-related roles
- 1.10 — KMS key rotation period ≤ 90 days
- 1.11 — Service account keys not created for default service accounts
- 1.14 — Default network not in use (project does not contain `default` VPC)
- 1.15 — Audit Configuration metadata not modified by service accounts

**2.x — Logging and Monitoring**
- 2.1 — Cloud Audit Logging configured for all services and users (`google_project_iam_audit_config` covers `allServices` or per-API)
- 2.2 — Sinks configured for all log entries
- 2.3 — Log bucket retention and locks configured
- 2.4 — Log metric filter and alerts for project ownership assignments
- 2.5 — Log metric filter and alerts for Audit Configuration changes
- 2.7 — Log metric filter and alerts for VPC network firewall rule changes
- 2.8 — Log metric filter and alerts for VPC network route changes
- 2.10 — Log metric filter and alerts for Cloud Storage IAM permission changes
- 2.13 — Cloud Asset Inventory enabled

**3.x — Networking**
- 3.1 — Default network not used in a project
- 3.6 — SSH (`tcp:22`) not exposed to `0.0.0.0/0`
- 3.7 — RDP (`tcp:3389`) not exposed to `0.0.0.0/0`
- 3.8 — VPC Flow Logs enabled for every subnet (sample rate ≥ 0.5, metadata = INCLUDE_ALL)
- 3.9 — DNSSEC enabled on Cloud DNS
- 3.10 — DNSSEC not using RSASHA1 for KSK
- 3.11 — DNSSEC not using RSASHA1 for ZSK

**4.x — Virtual Machines**
- 4.1 — Instances do not use default service account
- 4.2 — Instances do not use default SA with full access to all Cloud APIs
- 4.4 — Instances configured with OS Login
- 4.5 — Block project-wide SSH keys enabled on instances
- 4.7 — VM disks for critical instances are encrypted with CMEK
- 4.8 — Compute instances do not have public IPs
- 4.9 — Confidential Computing enabled on Compute Engine instances
- 4.11 — IP forwarding not enabled on instances

**5.x — Storage**
- 5.1 — Cloud Storage buckets are not anonymously or publicly accessible (`allUsers` / `allAuthenticatedUsers`)
- 5.2 — Cloud Storage buckets have uniform bucket-level access enabled
- 5.3 — Cloud Storage buckets have versioning enabled

**6.x — Cloud SQL Database Services**
- 6.1.1 — Cloud SQL instances do not have public IPs
- 6.1.2 — Cloud SQL instance "require SSL" enabled (`require_ssl = true`)
- 6.1.3 — Cloud SQL instances do not allow `0.0.0.0/0` in authorized networks
- 6.2.1 — Cloud SQL Postgres `log_checkpoints` flag enabled
- 6.3.1 — Cloud SQL SQL Server "external scripts enabled" flag off
- 6.4 — Cloud SQL instance backup configured (`backup_configuration { enabled = true }`)
- 6.5 — Cloud SQL high availability enabled (`availability_type = REGIONAL`)
- 6.6 — Cloud SQL instance deletion protection enabled

**7.x — BigQuery**
- 7.1 — BigQuery datasets are not anonymously or publicly accessible
- 7.2 — All BigQuery tables encrypted with CMEK
- 7.3 — Default CMEK set on BigQuery datasets

**8.x — GKE (formerly 7.x in earlier benchmark versions)**
- 8.1.1 — Image vulnerability scanning enabled (Container Analysis API)
- 8.2.1 — Minimize cluster admin role usage
- 8.4.1 — Cluster network policy enabled
- 8.4.2 — Cluster has Shielded GKE Nodes enabled
- 8.5.1 — Legacy ABAC disabled (`enable_legacy_abac = false`)
- 8.5.2 — Workload Identity enabled
- 8.5.3 — Private clusters enabled (`enable_private_nodes = true`)
- 8.5.4 — Master authorized networks configured
- 8.5.5 — Application-layer Secrets Encryption enabled (`database_encryption { state = "ENCRYPTED" }`)
- 8.6.1 — Container-Optimized OS (COS) used as node image
- 8.6.2 — Auto-upgrade enabled on node pools
- 8.6.3 — Auto-repair enabled on node pools
- 8.6.4 — Customer-Managed Encryption Keys for boot disks
- 8.7.1 — Logging enabled (`logging_service = "logging.googleapis.com/kubernetes"`)
- 8.7.2 — Monitoring enabled (`monitoring_service = "monitoring.googleapis.com/kubernetes"`)
- 8.8.1 — Basic authentication disabled (`master_auth { username = "" password = "" }`)
- 8.8.2 — Client certificate disabled (`client_certificate_config { issue_client_certificate = false }`)

When the benchmark version differs (CIS GCP 1.x vs 2.x vs 4.0) the chapter numbering shifts. The skill targets v4.0 by default. If the project's `.tf-analyze-ignore.yaml` declares a different benchmark version (`cis_version: 2.0`), use the operator's version and note it in the report header.

### Rules for the report

**Per-finding template** — every finding MUST include all of these fields:

```text
- **[CATALOGUE-ID#instance] <Title>** — <file:line> | Blast: <radius> | CIS: <id|n/a> | Effort: <Small|Medium|Large> | Status: <VERIFIED|NEEDS-REVIEW|SPECULATIVE>
  Description: <2-4 sentences explaining the issue and why it matters>
  Recommendation: <concrete fix, with diff snippet for non-obvious changes>
  Verification: <how an operator confirms the fix landed — exact command or grep pattern>
```

**Effort buckets** — every finding carries one:
| Bucket | Estimate | Examples |
|---|---|---|
| **Small** | ≤30 min, single file edit, no plan/apply | add `prevent_destroy`, add `description`, fix fmt |
| **Medium** | ≤2 h, multi-file or requires `terraform plan` review | refactor IAM to resource-level, add validation blocks across module, split a `for_each` |
| **Large** | ≥half-day, requires staged rollout, state surgery, or coordination | split state, rotate secrets, replace a chokepoint resource, migrate provider major version |

**Urgency caps per band** — to keep reports actionable, cap visible findings per urgency level:
| Urgency | Max shown in main body |
|---|---|
| CRITICAL | unlimited (always show all) |
| HIGH | 10 |
| MEDIUM | 15 |
| LOW | 10 |
| INFO | 5 |

When a band overflows, show the top N (sorted by blast radius descending, then by file density), and add a one-line note: `_… plus N additional MEDIUM findings, see Appendix C for the full list._` Write the overflow to a new `## Appendix C: full finding list` section **at the end of the report you generate** — this is an instruction to the report writer, not a reference to a section of this SKILL.md. Never silently drop findings — the catalogue join key in delta tracking depends on all detections being recorded.

**Auto-collapse empty sections** — if a section (Security, DRY, Style, etc.) has zero findings, replace its body with a single line: `_No findings — section omitted._` Do not emit empty subheadings.

**Surface positives in the executive summary** — before the finding count table, write one sentence calling out the strongest 1–3 positive findings ("Section 12") so the report doesn't read as purely punitive. Example: `_Strengths: state backend uses CMEK + versioning; all stateful resources carry prevent_destroy; CI runs tfsec + fmt + validate on every PR._`

**Other rules:**
- Group findings by section first, then by urgency within each section
- Action plan in section 13 should be actionable — someone should be able to pick up item 1 and start working
- Cross-reference related findings in the "Related Findings" subsection of the action plan
- When a finding matches an intentional pattern documented in CLAUDE.md, downgrade to INFO and note the source

---

## Step 17: Summary output

After writing the report, print a brief summary to the console:

```
Report written: reports/tf-analysis-YYYY-MM-DD-HHmmss.md
Health Grade: <A-F> (<score>/100)

Findings: N CRITICAL, N HIGH, N MEDIUM, N LOW, N INFO
Delta: +N new, -N resolved (vs YYYY-MM-DD-HHmmss)
Top priority: <one-line description of the #1 action item>
```

If `format:json` was requested, also write `reports/tf-analysis-YYYY-MM-DD-HHmmss.json` with the same data structured as:

```json
{
  "date": "YYYY-MM-DD-HHmmss",
  "scope": "...",
  "mode": "static|plan",
  "health_grade": "B",
  "health_score": 72,
  "summary": "...",
  "delta": {
    "previous_report": "YYYY-MM-DD-HHmmss",
    "resolved": ["SEC-GCP-IAM-001#1"],
    "new": ["MOD-PIN-001#1", "ROB-GCP-LIFECYCLE-002#3"],
    "unchanged": ["SEC-GCP-BUCKET-001#1", "SEC-PROVIDER-001#1"]
  },
  "findings": [
    {
      "catalogue_id": "SEC-GCP-IAM-001",
      "instance": 1,
      "section": "security",
      "urgency": "HIGH",
      "blast_radius": "infrastructure-wide",
      "cis_benchmark": ["1.6"],
      "title": "Project-level binding of overly broad role",
      "file": "terraform/modules/foo/iam.tf",
      "line": 42,
      "description": "...",
      "recommendation": "...",
      "verification": "...",
      "verification_status": "VERIFIED",
      "related_findings": ["ROB-GCP-LIFECYCLE-001"],
      "suppressed": false
    }
  ],
  "action_plan": [...]
}
```

---

## Step 18: Self-test mode (mode:self-test only)

If `mode:self-test` was specified, **skip all other steps**. The self-test is the regression suite for the skill itself: it asserts that every fixture under `fixtures/` produces exactly the catalogue IDs declared in its catalogue entries' `fixtures:` field.

### 18a. Run the self-test runner

The self-test is implemented as a Python script. From the skill directory:

```bash
python3 scripts/self_test.py
```

The runner does the following deterministically:

1. Walks `fixtures/` and lists every directory as a fixture.
2. For each fixture, derives the **expected** catalogue ID set by scanning `catalog/*.yaml` for entries whose `fixtures:` list contains the fixture name.
3. Invokes `scripts/detect.py --target fixtures/<NAME> --only-fixture <NAME> --format json` to get the **actual** catalogue ID set. The `--only-fixture` flag scopes the catalogue to the entries that declare the fixture, which prevents corpus-level patterns (e.g., `resource_absent` for `SEC-GCP-LOGGING-001`) from cross-contaminating unrelated fixtures.
4. Compares `expected` vs `actual` and prints `PASS` / `FAIL` per fixture.
5. Exits with code `0` if all fixtures pass, code `1` if any fixture has a mismatch.

### 18b. Outcome interpretation

| Outcome | Meaning | Action |
|---|---|---|
| **PASS** | Detected set == expected set | None |
| **FAIL: missing** | Expected ID was NOT detected | The catalogue pattern is wrong, the fixture has drifted, or `detect.py` has a bug. Inspect the fixture and pattern definition. |
| **FAIL: unexpected** | An unexpected ID fired | False positive — refine the catalogue pattern or correct the fixture. |
| **SKIP** | No catalogue entry declares this fixture | The fixture is orphaned. Add it to a catalogue entry's `fixtures:` field, or delete the fixture. |

### 18c. Catalogue-fixture cross-check (manual)

The self-test runner does not currently flag orphaned **catalogue entries** (entries that have no `fixtures:` field). Run this one-liner to find them:

```bash
python3 -c "
import sys; sys.path.insert(0, 'scripts')
from detect import load_yaml
from pathlib import Path
for y in sorted(Path('catalog').glob('*.yaml')):
    d = load_yaml(y.read_text())
    if d.get('status') == 'deprecated': continue
    if not (d.get('fixtures') or []):
        print('ORPHAN:', d['id'])
"
```

Every active catalogue entry should have at least one fixture. Orphans are tracked under task #46 (H3) and should be remediated by adding the corresponding fixture.

### 18d. When to run

- **Before committing any change to `catalog/`, `scripts/detect.py`, or `fixtures/`.** A green self-test is the contract that catalogue patterns still detect what they claim to detect.
- **After refactoring** the detection script's pattern handlers.
- **As part of CI** if the skill is checked into a repository — `python3 scripts/self_test.py` is suitable for a GitHub Actions step.

---

## Appendix A: IAM resource-level binding compatibility matrix

When recommending a switch from project-level IAM to resource-level IAM (Section 2b), consult this table first. Recommendations that name a non-existent resource type cause `terraform validate` failures and erode user trust in the report.

The matrix is keyed against **Google provider 6.x** unless noted. For other providers/versions, run the tempdir-validate procedure in Step 14a before recommending.

### Google Cloud (provider `hashicorp/google` ~> 6.0)

| Service | Resource-level binding exists? | Resource type | Notes |
|---|---|---|---|
| Cloud Storage bucket | ✅ | `google_storage_bucket_iam_member` / `_binding` / `_policy` | Use `_member` for additive grants |
| Spanner instance | ✅ | `google_spanner_instance_iam_member` | |
| Spanner database | ✅ | `google_spanner_database_iam_member` | Prefer this over instance-level when scoping reads/writes to one DB |
| Pub/Sub topic | ✅ | `google_pubsub_topic_iam_member` | |
| Pub/Sub subscription | ✅ | `google_pubsub_subscription_iam_member` | |
| BigQuery dataset | ✅ | `google_bigquery_dataset_iam_member` | Note: dataset access can also be set via `access` block on the dataset itself |
| BigQuery table | ✅ | `google_bigquery_table_iam_member` | |
| Cloud KMS key ring | ✅ | `google_kms_key_ring_iam_member` | |
| Cloud KMS crypto key | ✅ | `google_kms_crypto_key_iam_member` | |
| Secret Manager secret | ✅ | `google_secret_manager_secret_iam_member` | |
| Cloud Run service | ✅ | `google_cloud_run_service_iam_member` (v1) / `google_cloud_run_v2_service_iam_member` | |
| Cloud Run job | ✅ | `google_cloud_run_v2_job_iam_member` | |
| Cloud Function | ✅ | `google_cloudfunctions_function_iam_member` (v1) / `google_cloudfunctions2_function_iam_member` (v2) | |
| Service account (impersonation) | ✅ | `google_service_account_iam_member` | The "self-actAs" pattern uses this with `roles/iam.serviceAccountUser` |
| Compute instance | ✅ | `google_compute_instance_iam_member` | |
| Compute disk | ✅ | `google_compute_disk_iam_member` | |
| Compute subnetwork | ✅ | `google_compute_subnetwork_iam_member` | |
| Artifact Registry repository | ✅ | `google_artifact_registry_repository_iam_member` | |
| Source Repository | ✅ | `google_sourcerepo_repository_iam_member` | |
| Notebooks instance | ✅ | `google_notebooks_instance_iam_member` | |
| Dataproc cluster | ✅ | `google_dataproc_cluster_iam_member` | |
| Dataproc job | ✅ | `google_dataproc_job_iam_member` | |
| Endpoints service | ✅ | `google_endpoints_service_iam_member` | |
| Healthcare dataset | ✅ | `google_healthcare_dataset_iam_member` | |
| Cloud Tasks queue | ✅ | `google_cloud_tasks_queue_iam_member` | |
| **Cloud Workflows workflow** | ❌ | _none_ | Provider does not expose `google_workflows_workflow_iam_member` as of google 6.50. Grant `roles/workflows.invoker` at project level and rely on IAM Conditions or scoped service accounts. |
| **Cloud Build trigger** | ❌ | _none_ | Cloud Build does not support resource-level IAM. Grant `roles/cloudbuild.builds.editor` at project level. |
| **Cloud Scheduler job** | ❌ | _none_ | Scheduler IAM is project-scoped. |
| **Document AI processor** | ❌ | _none_ | Document AI does not support resource-level IAM. Grant `roles/documentai.apiUser` at project level. |
| **Vertex AI endpoint** | ❌ | _none_ | Vertex AI IAM is project-scoped. Use a dedicated service account per workload to limit blast radius. |
| **Cloud Logging sink** | ❌ | _none_ | Sinks have a writer identity, not an IAM policy of their own. |
| Cloud SQL instance | ❌ | _none_ | SQL IAM is project-scoped. Use database users for finer control. |

### AWS (provider `hashicorp/aws` ~> 5.0 / 6.0)

AWS IAM is structurally different — most resource-level access is expressed through resource policies, not IAM bindings. Consult these patterns:

| Service | Mechanism | Resource type |
|---|---|---|
| S3 bucket | Resource policy | `aws_s3_bucket_policy` |
| Lambda function | Resource policy | `aws_lambda_permission` |
| SNS topic | Resource policy | `aws_sns_topic_policy` |
| SQS queue | Resource policy | `aws_sqs_queue_policy` |
| Secrets Manager secret | Resource policy | `aws_secretsmanager_secret_policy` |
| KMS key | Key policy | `aws_kms_key.policy` (inline JSON) |
| ECR repository | Resource policy | `aws_ecr_repository_policy` |

If the codebase relies on identity-based policies attached to IAM roles, recommend scoping the role's policy document to specific resource ARNs rather than `Resource = "*"`.

### Azure (provider `hashicorp/azurerm` ~> 4.0)

Azure uses RBAC role assignments at any scope (subscription, resource group, resource). The resource is always `azurerm_role_assignment` with the `scope` argument naming the resource ID:

| Scope level | `scope` value |
|---|---|
| Resource | `azurerm_storage_account.example.id` |
| Resource group | `azurerm_resource_group.example.id` |
| Subscription | `data.azurerm_subscription.current.id` |

There are no service-specific role assignment resources — always use `azurerm_role_assignment` with the narrowest possible `scope`.

### When to recommend project-level IAM anyway

Even if a resource-level binding exists, project-level may be the right call when:
- The same role is granted to the same identity across many resources of the same type, AND a `for_each` over the resources would be more complex than the binding it replaces.
- The resource is created outside Terraform (operator-managed) and resource-level IAM would cause drift.
- The resource type does not exist yet at plan time (forward references would require multiple plan/apply cycles).

In these cases, document the project-level binding with a comment explaining the constraint and tag the finding **INFO** rather than HIGH/MEDIUM.

---

## Appendix B: Cost classification heuristics

Step 12 (Cost Estimation) prefers `infracost` when installed and falls back to relative size classes (XS/S/M/L/XL) otherwise. The skill deliberately does **not** maintain a per-SKU price table — those tables rot quickly and produce false precision because committed-use discounts, free tiers, and data egress dominate compute on real bills.

When classifying a resource into a size class without infracost, use these signals (deterministic, version-independent):

| Class | Compute signal | Storage signal | Managed-service signal |
|---|---|---|---|
| **XS** | Cloud Scheduler / EventBridge / Pub/Sub topic / single Lambda | <10 GB single bucket | Free-tier eligible managed service |
| **S** | `e2-medium` / `t3.medium` / `Standard_D2s_v5` (1 instance) | 10–100 GB | `db-f1-micro`, single Cloud Run / App Runner |
| **M** | `n2-standard-4` / `m5.large` / `Standard_D4s_v5` (1–3 instances) | 100–500 GB | Single GKE Standard / EKS / AKS cluster, 100-PU Spanner, single Cloud SQL / RDS instance |
| **L** | 4–10 instances of M-class compute, multi-AZ DB | 500 GB – 5 TB | Multi-node GKE/EKS, Cloud SQL HA, RDS Multi-AZ, Kendra Developer Edition |
| **XL** | Autoscaler ceiling >10 instances, multi-region | >5 TB | Multi-region Spanner, BigQuery slot reservations, Kendra Enterprise, large Vertex AI / SageMaker endpoints |

Multiply by `for_each` / `count` expansion (use plan JSON in `mode:plan`, otherwise the static literal). Apply a one-class bump for HA / multi-region / GPU. Anything above XL should be flagged in the report regardless of urgency — large resources warrant a second pair of eyes.

Refer operators to `infracost` or the official cloud pricing calculator for procurement-grade numbers. The skill's cost output is directional, not authoritative.

---

## Roadmap

Items that would extend `detect.py` beyond its current regex-first scope. None of these are wired — tracked here so future contributors don't re-discover the design space:

- **Structured HCL parsing.** Swap the regex scanner for `python-hcl2` as an optional dependency. Would improve recall on dynamic blocks, interpolation-inside-strings, and multi-line attribute values. The regex path stays as fallback so the skill remains stdlib-only by default.
- **External reconciler.** Read `tflint` / `tfsec` / `trivy` JSON output and cross-reference with catalogue IDs. Novel IDs become `--propose-stub` input; duplicates are collapsed by file+line fingerprint. Reduces double-reporting when teams run both this skill and a dedicated scanner.
- **Plan-time checks.** `mode:plan` already exists but is thinly implemented. Expand to parse `terraform show -json <plan>` for drift, destroy-on-create, and sensitive-attribute exposure that only manifest at plan time.
- **`TF_BINARY` env var** for pointing at `tofu` or a specific `terraform` build in hermetic environments. Currently the skill invokes `terraform` by name.
- **Dynamic block detection.** The regex scanner sees only static attribute values. `dynamic` blocks that conditionaly emit a security attribute (e.g., `dynamic "encryption_config"`) are treated as if the attribute is absent, generating false positives. A structured HCL parser or a two-pass regex (detect `dynamic "<arg>"`, evaluate its `for_each` condition) would close this gap.
- **MITRE ATT&CK mapping.** Each catalogue rule's `recommendation` text often maps to a specific ATT&CK Cloud technique (e.g., `T1078` — Valid Accounts, `T1530` — Data from Cloud Storage). Adding a `mitre_attack:` field to catalogue entries would allow MITRE-framed reports for red/blue team consumption and would improve the attack graph's narrative output.
- **`--only-new` baseline mode.** Add a `--baseline <previous-json>` flag that suppresses findings already present in a prior scan, emitting only net-new detections. This turns tf-analyze into a diff-mode scanner that works without a git history (useful for ad-hoc scans or state snapshots). The current `--diff-mode` requires a git repo; `--baseline` would work on any JSON output pair.
- **VS Code extension GA.** The `vscode-extension/` scaffold is TypeScript-complete. Next steps: add `terraform-ls` language server detection (to co-locate with the official HCL extension), add webview attack-graph rendering (d3.js SVG), publish to the VS Code Marketplace.
- **HCP Terraform Run Task.** Integrate as a [run task](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/settings/run-tasks) so findings appear in the HCP Terraform UI alongside plan output. The run task API accepts a webhook payload; `detect.py --format sarif` maps cleanly to the run task result schema.
