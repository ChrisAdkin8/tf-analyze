# Changelog

Rule counts and corpus finding counts are as of each round's commit.
Self-test fixture counts are cumulative.

---

## v0.1.0 — 2026-05-09

**First public release.** Cuts a stable tag against everything
shipped through Round 26 + VS Code extension v0.1.19. Triggers the
Docker workflow to publish `ghcr.io/chrisadkin8/tf-analyze:v0.1.0`
(multi-arch `linux/amd64` + `linux/arm64`) and the new release
workflow to attach the bundled `.vsix` to the GitHub Release page.

`action.yml` now lives at repo root, so the GitHub Release page
gains a "Publish to Marketplace" toggle. Single-line CI install
becomes:

```yaml
- uses: ChrisAdkin8/tf-analyze@v0.1.0
  with:
    fail-on: HIGH
    post-pr-comment: true
```

Highlights of what's in this release (full detail in the round
sections below):

- **209 rules**, 100% with `fix_hcl`, MITRE ATT&CK on 48
- Attack-path graph + adversarial scenario narratives
- IAM analysis covers both `data "aws_iam_policy_document"` AND inline `policy = jsonencode({...})`
- Kubernetes (PSA / NetworkPolicy / cluster-admin RBAC) and Helm (LoadBalancer / privileged) coverage
- Deterministic risk score (0–100, A/B/B-/C/D/F) emitted in JSON / text / HTML
- Baseline ratcheting (`--baseline prior.json`) for legacy-repo adoption
- VS Code extension v0.1.19 with bundled engine, real-time LSP diagnostics, status-bar shortcuts (scan / graph / delta / compliance / remediate), bulk remediation panel, baseline UI
- Composite GitHub Action with inline PR `suggestion` blocks + SARIF upload + HTML artefact + score/grade/counts as workflow outputs
- Multi-arch Docker image with `python-hcl2` bundled

411 tests passing. See `docs/launch/release-notes.md` for the
launch-day version of these notes.

---

## VS Code extension v0.1.8 — 2026-05-09

**Hotfix: attack-graph webview rendered an empty panel.**

Root cause: the webview read the graph JSON from `data.attack_graph`, but the engine has emitted it at `data.graph` since Round 25 (`output["graph"] = attack_graph` in `detect.py`). The optional-chain `?? graph` fell silently through to an empty placeholder; every render produced a blank SVG with no diagnostic.

Verified against `examples/terragoat/aws/`: 46 nodes, 5 edges, 1 critical edge correctly populated after the fix.

**Three other bugs surfaced while debugging the blank-panel report:**

1. Critical-path edges weren't highlighted. The webview was matching `edge.label === 'critical'`, but edge labels are real relationship names (`security_group`, `iam`, etc.). Critical-path data lives at `graph.critical_path` as a node-ID list. Webview now derives `is_critical` per edge by walking consecutive pairs.
2. The single `try/catch` block swallowed every failure mode — exec error, parse error, empty graph — and rendered a blank SVG. Four dedicated error panels now report the failure class, underlying stderr, and the offending command.
3. Graph view and main scan used different `detect.py` resolution paths. The graph view couldn't find the script in workspaces with tf-analyze cloned next to the user's TF code. Both surfaces now use the same resolver: `scriptPath` setting → `<ws>/scripts/detect.py` → `<ws>/detect.py` → `../tf-analyze/scripts/detect.py`.

Built artefact: `vscode-extension/tf-analyze-0.1.8.vsix`. CHANGELOG entry under `vscode-extension/CHANGELOG.md`.

---

## VS Code extension v0.1.7 — 2026-05-09

**One-click attack-graph shortcut in the status bar.**

The attack-graph view was previously only reachable from three places — Command Palette, Findings view title bar, walkthrough — none of them as discoverable as the scanner's most distinctive feature deserves. The new status-bar item sits next to the existing `🛡 tf-analyze` scan shield (priority 99 — to its right) and opens the graph webview on click.

The shortcut is hidden when the workspace has no `.tf` files, so non-Terraform projects don't see a useless button. Visibility is checked once at activation via `vscode.workspace.findFiles("**/*.tf", "**/node_modules/**", 1)`.

Built artefact: `vscode-extension/tf-analyze-0.1.7.vsix`. README and `docs/vscode-extension.md` updated to describe both status-bar items as a pair.

---

## Round 26 — 2026-05-08

**Tier A correctness gaps + Tier B detection depth (411/411 tests passing).**

### Tier A — correctness gaps that would have bitten real users

- **A1: `iam_json_policy_analysis` pattern kind.** Walks `policy = jsonencode({...})` blocks on `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_iam_group_policy`. Same six checks as the data-source variant. Ships 4 rules (`SEC-AWS-IAM-JSON-001..004`) covering wildcard action, `iam:*` privesc, full-admin, public principal. Closes the largest detection gap vs. tfsec/checkov.
- **A2: All stale `hashicorp/tf-analyze` references replaced with `ChrisAdkin8/tf-analyze`.** README, TODO, PLAN, docker workflow. Quickstart paths now actually work on first contact (was 404 across the board).
- **A3: `tests/test_apply_fixes.py` round-trip tests.** New file: copy fixture → `--apply-fixes apply` → re-scan → assert finding cleared + balanced braces + `.bak` backup written. Surfaced and documented two engine limitations (`fire_if_absent` rules and `nested_path` `resource_missing_arg`). Adds a wider corruption-safety net that asserts no patcher run produces brace-imbalanced source.
- **A4: Multi-file fixtures + `tests/test_multi_file.py`.** Four representative layouts: `_multi_variables_split` (variables.tf separation), `_multi_module_input` (parent/child), `_multi_provider_aliases` (multi-region), `_multi_outputs_sensitive_leak`. Surfaced and fixed a comment-stripping bug in the module-input flow-through extractor (caller's `module "x" { encrypted = false  # note }` was flowing the literal `"false # note"`).
- **A5: Scoring-version stability tripwire.** `tests/test_output_formats.py::test_scoring_constants_pinned_to_v1` locks `_RISK_WEIGHTS`, `_GRADE_TIERS`, `_SCORING_VERSION` to documented values. Future weight changes must be deliberate version bumps.

### Tier B — depth-of-detection gaps

- **B6: Kubernetes resource rules.** `SEC-K8S-PSA-001` (namespace missing PSA enforce label, HIGH), `SEC-K8S-NETPOL-001` (corpus has namespaces but no network policies, HIGH), `SEC-K8S-RBAC-001` (`cluster-admin` ClusterRoleBinding, CRITICAL).
- **B7: `applies_when:` version gating.** Engine support already existed; this round added contract tests + documentation + annotated 2 rules with real version dependencies (`STK-GCP-CLOUDSQL-004` requires google ≥4.0 for `ssl_mode`; `STK-AWS-LAUNCH-TEMPLATE-001` requires aws ≥3.0 for `metadata_options`).
- **B9: `helm_set_value` pattern kind + 2 rules.** Walks `resource "helm_release" { set { name = "..."; value = "..." } }` blocks. Ships `SEC-K8S-HELM-001` (`service.type=LoadBalancer` exposes pods publicly, HIGH) and `SEC-K8S-HELM-002` (`securityContext.privileged=true` allows host breakout, CRITICAL).

### Engine fixes surfaced this round

- **Module-input flow-through dropped trailing comments into the propagated value** (`encrypted = false  # note` flowed as `"false # note"`, breaking downstream comparisons). Fixed in both the locals extractor and the module-call extractor.
- **`re.compile(r'^(?i)true$')` no longer compiles in Python 3.11+** (global flags must be at start). Inline-flag pattern in helm value regex moved to `(?i)^...$`. The schema validator should probably reject mid-pattern global flags going forward; flagged in TODO.

### New tests: 411 (was 382)

| File                          | Tests | Notes                                                                  |
|-------------------------------|------:|------------------------------------------------------------------------|
| `test_apply_fixes.py`         |     7 | NEW — round-trip + brace-corruption safety net                         |
| `test_multi_file.py`          |     4 | NEW — cross-file resolution paths                                      |
| `test_detection_core.py`      |    +5 | applies_when gating tests                                              |
| `test_output_formats.py`      |    +1 | scoring-constants pinned                                               |
| `test_fixtures.py`            |   +13 | new IAM-JSON, K8s, Helm fixtures                                       |

### Catalog: 200 → 209 active rules

| Family                     | Rules added | Notes                                                          |
|----------------------------|------------:|----------------------------------------------------------------|
| AWS IAM (inline JSON)      |           4 | `SEC-AWS-IAM-JSON-001..004`                                    |
| Kubernetes                 |           3 | `SEC-K8S-PSA-001`, `SEC-K8S-NETPOL-001`, `SEC-K8S-RBAC-001`    |
| Helm                       |           2 | `SEC-K8S-HELM-001..002`                                        |
| Total                      |           9 | All ship with positive fixtures; auto-generated clean fixtures where the kind supports it |

---

## Round 25 — 2026-05-08

**Risk score / letter grade now emitted by `detect.py` (381/381 tests passing).**

Closes a long-standing gap between SKILL.md and the CLI: SKILL.md described a "deterministic risk score" as a top-level capability, but the engine never emitted it — every CI integration on top of `--format json` had to re-implement the formula, with no guarantee that the LLM-driven markdown report and the CLI agreed on the number.

### Changes

- **New `_compute_summary()`** in `scripts/detect.py` — single source of truth for the score, grade, urgency counts, and `scoring_version`. SKILL.md now references the engine's constants rather than duplicating the formula.
- **`summary` block in JSON output** — always present, never optional. Keys: `scoring_version`, `score`, `grade`, `counts`, `suppressed_count`, `formula`. Stable across releases; weight changes bump `_SCORING_VERSION` so downstream gates pin to a specific weighting.
- **One-line score header in text output** — first line of every text-format scan, e.g. `# tf-analyze: 82 (B) · 0 CRITICAL · 0 HIGH · 4 MEDIUM · 6 LOW · 0 INFO`.
- **Colour-banded score banner in HTML** — rendered above the findings panel; A=green, B=lime, C=amber, D/F=red. Includes the formula text and `scoring_version` for traceability.
- **`tests/test_output_formats.py` (NEW, 17 tests)** — pyramid-bottom contract tests covering `_compute_summary` formula correctness, grade boundaries, half-weight suppressed contribution, JSON/text/HTML emission, and SARIF / HTML well-formedness. SKILL.md's worked examples are encoded as test cases.
- **SARIF skipped intentionally** — SARIF v2.1.0 has no canonical aggregate-score slot; tooling doesn't expect one.
- **No `--exit-on-grade` flag** — `--fail-on HIGH` already exists and gates on finding kind. A grade gate invites suppression-to-bump-score gaming and was deliberately not added.

### Test count: 364 → 381 (+17)

| Source                     | Tests | Notes                                                                |
|----------------------------|-------|----------------------------------------------------------------------|
| `test_output_formats.py`   | 17    | NEW — `_compute_summary`, grade boundaries, JSON/text/HTML contract |

---

## Round 24 — 2026-05-08

**Tier 1/2/3 implementation: detection depth, MITRE mapping, baseline ratcheting, HCP run task (364/364 tests passing).**

### Tier 1 — detection depth

1. **Auto-scaffolded clean fixtures: 26 → 131.** New `scripts/gen_clean_fixtures.py` generates `fixtures/<rule-id>_clean/main.tf` from each rule's `fix_hcl`. Caught **4 real false positives** the moment they ran:
   - `SEC-AWS-LB-LISTENER-001` — fired on the redirect-only HTTP listener pattern
   - `SEC-AZURE-KV-002`, `STK-AWS-LAUNCH-TEMPLATE-001` — `hcl_attr` quote-handling bug (`not_equal: '"Deny"'` vs unwrapped `"Deny"` value)
   - `STK-GCP-CLOUDSQL-004` — stale rule still expected legacy `require_ssl` when fix uses modern `ssl_mode = "ENCRYPTED_ONLY"`

   Engine fixes:
   - `hcl_attr` now strips quotes and resolves `var.X` before `not_equal` comparison
   - New `suppress_if_body_contains: '<substring>'` field on `resource_arg`, `resource_missing_arg`, `hcl_attr`

2. **Variable resolution: ternary + module-input flow-through.** `_resolve_var_ref` now folds `var.x ? "a" : "b"` when the condition has a known boolean default. `_extract_var_defaults_by_dir` propagates `module "child" { source = "./c"; foo = bar }` overrides into the child module's directory-scoped var dict, so parent-supplied values resolve through child rules.

3. **`iam_policy_analysis` pattern kind + 6 new rules.** Walks every `data "aws_iam_policy_document"` block and inspects each `statement {}`. Skips `Effect = "Deny"`. Six checks shipped:
   - `SEC-AWS-IAM-POLICY-001` — wildcard `actions = ["*"]` (HIGH)
   - `SEC-AWS-IAM-POLICY-002` — `iam:*` privesc (CRITICAL)
   - `SEC-AWS-IAM-POLICY-003` — wildcard `resources = ["*"]` (HIGH)
   - `SEC-AWS-IAM-POLICY-004` — public principal (CRITICAL)
   - `SEC-AWS-IAM-POLICY-005` — full admin (action+resource both `*`) (CRITICAL)
   - `SEC-AWS-IAM-POLICY-006` — `not_actions` / `not_resources` on Allow (MEDIUM, demoted from HIGH after calibration)

4. **`python-hcl2` default-on.** Was opt-in via `--use-hcl2`; now auto-enabled when the dependency is installed, with a one-line stderr notice when it isn't. Opt-out with `--no-hcl2` or `TF_ANALYZE_NO_HCL2=1`. Dockerfile bundles `python-hcl2==4.3.5`.

5. **Resource-address propagation audit.** Audited all 54 `findings.append(…)` sites; the only remaining empty-`resource` case (the `grep` pattern kind) now does best-effort attribution by walking enclosing `resource`/`data` blocks. Attack-graph attachment now works for grep-shaped rules too.

### Tier 2 — quality and credibility

6. **MITRE ATT&CK mapping.** 48 catalogue rules now carry a `mitre:` field (T1078.004, T1098.001, T1530, T1552.001, T1552.005, T1562.001, T1562.008, T1611, T1071.001, T1190, T1133, T1195.002, T1556.006, T1059). New `--format mitre` groups findings by technique. SARIF output gets `mitre:Tnnnn` tags. Mapping script: `scripts/apply_mitre.py` (idempotent re-runs).

7. **Performance ceiling test (`tests/test_perf.py`).** Single-process scan of the 219-fixture corpus must finish in <5s. Current actuals: **329 files / 200 rules / 1624 findings in 0.35s** — 14× under the budget. Skip with `TF_ANALYZE_SKIP_PERF=1` on noisy CI runners.

8. **`--baseline prior.json` flag.** New `apply_baseline()` filters current findings against a snapshot using `(id, file, line, resource)` as the join key. Suppressed-by-baseline findings appear under `suppressed_by_baseline` in the JSON output; only retained findings affect the `--fail-on` exit code. Designed for ratcheting on legacy repos.

9. **Severity calibration log (`docs/severity-calibration.md`).** Documented methodology, two adjustments this round, and standing decisions. Net moves: `SEC-AWS-CLOUDTRAIL-001` HIGH→CRITICAL, `SEC-AWS-IAM-POLICY-006` HIGH→MEDIUM.

10. **HCP Terraform Run Task server stub (`integrations/run-task/`).** FastAPI server that receives webhook callbacks from HCP Terraform between plan and apply, downloads plan-JSON, runs `detect.py --plan-json`, posts `passed` / `failed` back. HMAC-SHA512 signature verification. Dockerfile bundled. Walkthrough in `docs/run-task.md`.

### Tier 3 — polish

- **`docs/custom-rules.md`** — worked example (company-wide `cost_center` tag), schema reference, suppression mechanisms, testing pattern.
- **Provider `default_tags` propagation** — when the AWS provider in a directory declares `default_tags { ... }`, `OPS-AWS-TAGS-*` and any `aws_*` rule whose target arg is `tags` is suppressed. No more "missing tags" findings on resources whose tags are injected by the provider.
- **VS Code adversarial narrative** — extension hover panel now shows `narrative`, `mitre`, and styled `fix_disruption` badges. New per-finding `narrative` field is added by `_enrich_findings_for_output()`. New narratives shipped for the 4 IAM-POLICY rules.

### Test count: 246 → 364

| Source                     | Tests | Notes                                                                       |
|----------------------------|-------|-----------------------------------------------------------------------------|
| `test_fixtures.py`         | 193   | All 193 positive fixtures (was 187)                                         |
| `test_clean_fixtures.py`   | 131   | All 131 clean fixtures (was 26 — coverage 13% → ~67% of active rules)       |
| `test_detection_core.py`   | 28    | +5 ternary + module-input tests                                             |
| `test_attack_graph.py`     | 8     | unchanged                                                                   |
| `test_custom_rules.py`     | 3     | unchanged                                                                   |
| `test_perf.py`             | 1     | NEW — corpus-scan budget guard                                              |

---

## Round 21 — 2026-05-08

**100% fix_hcl coverage, pre-commit hook, VS Code extension, SKILL.md re-scan (192/192 fixtures):**

### 1. fix_hcl coverage: 100% (was 80%)

Added `fix_hcl` and `fix_disruption` to all 38 remaining catalogue rules that lacked them. Every rule now has a canonical HCL snippet showing the correct configuration. Rules where the fix is "remove code" (ROB-UNUSED-001/002, ROB-MOVED-001, ROB-REMOVED-001) include commented-before/after patterns showing the removal intent.

**Categories covered:**
- Cost controls: `COST-AWS-RISK-001`, `COST-GCP-RISK-001`
- Module supply chain: `MOD-SUPPLY-002`, `MOD-STALE-001`
- Robustness: `ROB-BACKEND-001`, `ROB-MOVED-001`, `ROB-REMOVED-001`, `ROB-VALIDATION-002`, `ROB-VERSION-002/003`, `ROB-COUNT-001/002`, `ROB-COUNTREF-001/002`, `ROB-FOREACH-001`, `ROB-PROVIDER-ALIAS-001/002`, `ROB-UNUSED-001/002`
- Security: `SEC-AWS-ACCESSKEY-001`, `SEC-EPHEMERAL-001`, `SEC-GCP-SA-KEY-001`, `SEC-DATASOURCE-001/002`, `SEC-SENSITIVE-001/002/003`, `SEC-SECRETS-001`, `SEC-STATE-001`, `SEC-PROVISIONER-001`, `SEC-GCP-IAM-003`
- Intent: `INT-INTENT-001/002/004`
- GCP stack: `STK-GCP-DEPRECATION-001`, `STK-GCP-KMS-LOCATION-001`
- Style/CI: `STYLE-DESC-001`, `CI-TEST-001`

### 2. Pre-commit hook

Added `.pre-commit-hooks.yaml` at the repo root defining three hook variants:
- `tf-analyze` — all sections, fail on HIGH+
- `tf-analyze-security` — security section only, fail on HIGH+
- `tf-analyze-critical` — all sections, fail on CRITICAL only

See `docs/pre-commit.md` for setup and CI integration instructions.

### 3. VS Code Extension (`vscode-extension/`)

New TypeScript VS Code extension (`vscode-extension/src/extension.ts`):
- Inline diagnostics (error/warning/info by urgency threshold)
- Quick Fix (⌘.) to insert `fix_hcl` snippets at the affected line
- "View recommendation" code action opens a webview with full details
- **Findings tree** in the Explorer sidebar, grouped by catalogue section
- **Status bar** showing `C/H/M` counts; click to re-run
- **Auto-scan on save** for `.tf` files (configurable via `tf-analyze.runOnSave`)
- Settings: `tf-analyze.scriptPath`, `tf-analyze.failOn`, `tf-analyze.section`, `tf-analyze.extraArgs`

See `docs/vscode-extension.md` for installation and architecture.

### 4. Documentation

- `docs/pre-commit.md` — pre-commit setup, CI usage, hook customisation
- `docs/vscode-extension.md` — extension installation, features, configuration, architecture
- `README.md` — new "Integrations" section covering pre-commit + VS Code extension
- `SKILL.md` — Roadmap expanded with 5 new items: dynamic block detection, MITRE ATT&CK mapping, `--only-new` baseline mode, VS Code extension GA, HCP Terraform Run Task integration

### 5. SKILL.md deep re-scan

Re-analysed SKILL.md for gaps and improvements. Additions:
- **Dynamic block detection** (roadmap) — the regex scanner misses `dynamic` blocks that conditionally emit security attributes; structured HCL parsing or two-pass regex would close this gap.
- **MITRE ATT&CK mapping** (roadmap) — adding `mitre_attack:` fields to catalogue entries enables red/blue team framing in reports.
- **`--only-new` baseline mode** (roadmap) — `--baseline <prior.json>` to suppress already-known findings, enabling diff-mode scans without git.
- **VS Code extension GA** (roadmap) — attack-graph webview (d3.js), terraform-ls co-location, Marketplace publication.
- **HCP Terraform Run Task** (roadmap) — webhook integration so findings appear in HCP Terraform UI.

---

## Round 20 — 2026-05-08

**Detection quality, fix_hcl coverage, and new cloud service rules (192/192 fixtures):**

### 1. Detection quality fixes (Round 19 carry-over)

- **`verification` fields** added to 3 catalogue YAML files that were missing them (`ROB-AWS-BACKUP-001`, `SEC-AWS-GUARDDUTY-001`, `SEC-AWS-SECURITYHUB-001`), resolving 3 failing fixtures.
- **`when_present` gates** added to all 3 `resource_absent` rules to prevent false positives on non-AWS Terraform codebases (GCP-only fixtures no longer trigger AWS-specific absence rules).

### 2. New catalogue rules (15 rules, 15 fixtures)

| Rule | Title | Urgency |
|------|-------|---------|
| `SEC-AWS-MSK-001` | MSK cluster allows unencrypted client-broker traffic | HIGH |
| `SEC-AWS-MSK-002` | MSK cluster does not use CMK for encryption at rest | MEDIUM |
| `SEC-AWS-KINESIS-001` | Kinesis Data Stream not encrypted with KMS | MEDIUM |
| `SEC-AZURE-EVENTHUB-001` | Event Hub namespace does not use CMK encryption | MEDIUM |
| `SEC-AZURE-SERVICEBUS-001` | Service Bus namespace does not use CMK encryption | MEDIUM |
| `SEC-AWS-CWL-001` | CloudWatch log group not encrypted with KMS CMK | MEDIUM |
| `OPS-AWS-CWL-001` | CloudWatch log group has no retention policy | LOW |
| `SEC-AWS-REDSHIFT-001` | Redshift cluster encryption disabled | HIGH |
| `ROB-AWS-REDSHIFT-001` | Redshift cluster has no automated snapshot retention | MEDIUM |
| `SEC-AWS-DOCDB-001` | DocumentDB cluster storage not encrypted | HIGH |
| `SEC-AWS-NEPTUNE-001` | Neptune cluster storage not encrypted | HIGH |
| `SEC-AWS-IAM-003` | IAM account password policy not configured or too weak | MEDIUM |
| `SEC-AZURE-REDIS-001` | Azure Redis Cache allows non-TLS connections | HIGH |
| `SEC-AWS-ATHENA-001` | Athena workgroup results not encrypted | MEDIUM |
| `SEC-GCP-COMPUTE-DISK-001` | GCP compute disk not encrypted with CSEK/CMEK | MEDIUM |

All 15 rules include `fix_hcl`, `fix_disruption`, `verification`, and fixtures.

### 3. `fix_hcl` coverage lifted from ~40% to 80%

Added `fix_hcl` + `fix_disruption` fields to **~100 existing catalogue rules** that were missing them, spanning all three cloud providers and all rule categories (SEC, ROB, STK, OPS, MOD). Coverage: **156/194 rules (80%)**.

Key additions by category:
- **AWS**: S3 public-access block, S3 access logging, VPC flow logs, LB HTTP redirect, SSM SecureString, CloudFront HTTPS, IAM wildcard principal, EKS (private endpoint, secrets encryption, OIDC, log types), ECR lifecycle, Redshift, DocumentDB, Neptune, Athena, MSK, Kinesis
- **Azure**: AKS (RBAC, network policy, workload identity, private cluster, IP ranges), ACR admin, Redis TLS, Service Bus/Event Hub CMK, SQL AAD admin, storage soft-delete, NSG flow logs, Key Vault diagnostics, App Service HTTPS/IP restrictions
- **GCP**: IAM broad roles, public IP, Cloud SQL public IP, CloudRun ingress, compute SA, GKE (private nodes, workload identity, secrets encryption, master auth networks, node pool shielded), DNS DNSSEC, KMS rotation, Pub/Sub CMK, BigQuery CMK, Artifact Registry CMK, Cloud SQL backup/deletion protection, bucket versioning/public access prevention, GCS logging target, firewall (SSH, RDP, DB ports), subnet flow logs, Cloud Audit Logs
- **Cross-provider**: Module pinning, supply chain, backend locking, remote state decoupling, variable validation, lifecycle rules, provider version bounds

---

## Round 18 — 2026-05-08

**Bug-fix round: `--apply-fixes` nested blocks + `block_has_arg` false positives (166/166 fixtures):**

### 1. `--apply-fixes` nested block support

`_fix_line_for_arg()` previously only handled flat `arg = value` assignments and returned `None` for nested block fix_hcl entries like `dead_letter_config { ... }` or `tags = { ... }`. Applying fixes silently produced 0 patches for 7 of the 47 fixable rules.

- Added `_fix_hcl_body()` helper to strip outer resource wrapper from fix_hcl snippets.
- Updated `_fix_line_for_arg()` to handle multi-line map literals (`tags = { ... }`): detects unmatched `{` on the first line, then brace-matches to extract the full expression. Returns raw (unstripped) text so relative indentation is preserved.
- Added `_fix_block_for_nested_arg()`: brace-matches `arg { ... }` syntax in fix_hcl and returns the complete raw block text.
- Added `_reindent_fix_snippet(raw, indent) -> list[str]`: strips the fix_hcl base indentation from all lines, prepends the actual file's indentation, returns newline-terminated lines ready for list insertion.
- Updated `_handle_apply_fixes()` for `resource_missing_arg`: uses `_fix_line_for_arg or _fix_block_for_nested_arg` with `_reindent_fix_snippet`, inserting all lines atomically via `modified[block_end:block_end] = insert_lines`.

### 2. `_handle_apply_fixes` off-by-one in `start_idx`

`RESOURCE_START` regex (`^\s*resource`) with `re.MULTILINE` can match a blank line before the resource keyword due to `\s*` consuming `\n`. This made `start_idx` point to the blank line, causing `_block_indent` to pick up the `resource` declaration line (0 indentation) as the first "valid" content, returning `""` as the indent string. All inserted fixes had no indentation.

- Added a forward scan in `_handle_apply_fixes`: after computing `start_idx`, advance past lines without `{` to reach the actual resource opening.

### 3. `block_has_arg` now detects nested block declarations

`block_has_arg(body, arg)` previously only matched `arg =` (attribute assignment). Arguments that appear as block syntax (`arg {`) were not detected, causing false positives for `resource_missing_arg` rules where the block exists but an inner attribute is absent.

- Extended regex from `arg\s*=` to `arg\s*[={]`.
- Also changed `resource_missing_arg` detection to prefer `nested_path` over `arg` when both are set in a pattern. This ensures `SEC-AZURE-WEBAPP-001` uses `site_config.ip_restriction` (the deep check) rather than `site_config` (shallow), correctly firing when `site_config {}` is present but `ip_restriction` is absent.

### 4. `STK-AWS-LAMBDA-003` false positive fixed

Consequence of fix 3: `STK-AWS-LAMBDA-003` (`tracing_config` missing) no longer fires when `tracing_config { mode = "Active" }` is present in the resource body.

Self-test: 166/166 (unchanged).

---

## Round 17 — 2026-05-08

**Eight Tier-1 improvements: auto-fix, dynamic blocks, DynamoDB coverage, ECS coverage, WAFv2 coverage, caching, graph checks (+~250 lines detect.py, +6 rules, +6 fixtures):**

### 1. `--apply-fixes` Auto-Remediation

New `--apply-fixes [dry-run|apply]` flag applies `fix_hcl` patches directly to `.tf` files for fixable findings.

- `dry-run`: prints a unified diff to stdout, no files written. Safe to run in CI.
- `apply`: writes patched files to disk; creates `.bak` backups before mutating.
- Processes findings in reverse line order per file so multi-fix insertions don't shift positions.
- Handles `resource_missing_arg` (inserts missing attribute before closing `}`) and `resource_arg`/`hcl_attr` (replaces the wrong-value line).
- New helper functions: `_fix_line_for_arg()`, `_find_block_end_in_lines()`, `_block_indent()`, `_handle_apply_fixes()`.
- `difflib` and `shutil` added to imports.

### 2. Dynamic Block Expansion

`detect_in_file()` now expands `dynamic "X" { for_each = ... content { ... } }` blocks into `X { ... }` before running pattern checks.

- New `_expand_dynamic_blocks(body)` text pre-pass replaces each dynamic block with its `content {}` body as a plain block.
- Applied to every resource block's body after extraction, before attribute inspection.
- Eliminates false negatives where security attributes live inside dynamically-generated nested blocks (e.g., `dynamic "ingress"` in security groups, `dynamic "container"` in ECS).
- Line numbers are unaffected: the finding still reports the resource block's `start_line`, not a position inside the expanded body.

### 3. Incremental Scan Cache (`--cache`)

New `--cache` flag stores findings in `.tf-analyze-cache.json` keyed on a hash of all `.tf` file contents + catalogue rules.

- `--cache`: enables caching with default location `<target>/.tf-analyze-cache.json`.
- `--cache-file PATH`: override the cache file location.
- Cache is invalidated automatically when any `.tf` file or catalogue rule changes.
- On cache hit, the full scan (detect_in_file loop + detect_corpus) is skipped; findings are returned instantly.
- Plan-time (`--plan-json`) and registry staleness (`--check-registry`) findings are not cached (they depend on external inputs).
- New helpers: `_corpus_hash()`, `_load_scan_cache()`, `_save_scan_cache()`.

### 4. DynamoDB Security Rules (3 new rules)

- `ROB-AWS-DDB-001` — Missing `deletion_protection_enabled`. Default is `false`; uses `resource_missing_arg` + `hcl_attr not_equal:true`.
- `ROB-AWS-DDB-002` — PITR disabled or absent. Graph check `dynamodb_pitr` verifies `point_in_time_recovery { enabled = true }`.
- `SEC-AWS-DDB-001` — Server-side encryption using Amazon-owned keys instead of customer-managed KMS. Graph check `dynamodb_sse` verifies `server_side_encryption { kms_key_arn = ... }`.

### 5. ECS Task Definition Security Rules (2 new rules)

- `SEC-AWS-ECS-001` — Secrets in plaintext `environment` variables. Grep pattern matches both HCL `name = "DB_PASSWORD"` and JSON `"name": "DB_PASSWORD"` formats.
- `SEC-AWS-ECS-002` — Privileged container (`privileged = true` or `"privileged": true`). Grep pattern handles both HCL and JSON formats.

### 6. WAFv2 Logging Rule (1 new rule)

- `SEC-AWS-WAF-001` — `aws_wafv2_web_acl` exists but no `aws_wafv2_logging_configuration` is defined. Uses `resource_absent` with `when_present: aws_wafv2_web_acl`.

### 7. New Graph Check Functions

- `_graph_dynamodb_pitr(index, all_files_text)` — fires `ROB-AWS-DDB-002`.
- `_graph_dynamodb_sse(index, all_files_text)` — fires `SEC-AWS-DDB-001`.
- Both registered in `_GRAPH_CHECKS`.

### Infrastructure

- `--apply-fixes` argument added (`dry-run`/`apply`).
- `--cache` and `--cache-file` arguments added.
- `docs/cli.md` regenerated.
- Self-test: 166/166 fixtures passing (was 160/160; +6 new fixture sets).

---

## Round 16 — 2026-05-08

**Nine improvements: variable resolution, fix_hcl coverage, multi-framework compliance, registry staleness, Azure/GCP attack graph, subagent decomposition, LLM calibration, CI PR comments (+~300 lines detect.py, +68 catalogue entries, +1 rule, +1 fixture):**

### 1. Variable Reference Resolution

`detect_in_file()` now substitutes `var.X` attribute values with declared variable defaults before evaluating `resource_arg` patterns. A resource like `enable_key_rotation = var.rotation` where `variable "rotation" { default = false }` now correctly fires the relevant rule instead of silently passing.

- New `_extract_var_defaults_by_dir(all_files_text)` — scans all `.tf` files in scope for `variable "X" { default = Y }` blocks; returns a per-directory map.
- New `_resolve_var_ref(val, var_defaults)` — substitutes `var.X` with its default if known; returns original value otherwise.
- Scoped per-directory to match Terraform's actual variable resolution semantics.
- Applied at both `resource_arg` value check and `suppress_if` check in `detect_in_file()`.

### 2. fix_hcl Coverage (+38 catalogue entries)

Added `fix_hcl` and `fix_disruption` fields to the 38 highest-value rules across security, robustness, and ops categories. These power `--show-fixes` inline remediation suggestions and the HTML "Suggested fix" panels.

- **Security encryption/access (15):** SEC-AWS-EBS-001, SEC-AWS-RDS-002, SEC-AWS-SNS-001, SEC-AWS-SQS-001, SEC-AWS-ELASTICACHE-001, SEC-AWS-COGNITO-001, SEC-AWS-CLOUDTRAIL-001/002, SEC-AZURE-KV-001/002, SEC-AZURE-STORAGE-001/002, SEC-AZURE-VM-001, SEC-GCP-REDIS-001/002.
- **Robustness data-protection (9):** ROB-AWS-RDS-001/002/003, ROB-AWS-S3-001, ROB-AWS-LIFECYCLE-002, ROB-AZURE-LIFECYCLE-001, ROB-AZURE-SQL-001, ROB-AZURE-STORAGE-001, ROB-GCP-LIFECYCLE-001.
- **Ops/tagging (3):** OPS-AWS-TAGS-001, OPS-GCP-LABELS-001, OPS-AZURE-TAGS-001.
- **CI/logging (11):** SEC-AWS-APIGW-001, SEC-AWS-CLOUDFRONT-002, STK-GCP-CLOUDSQL-004, STK-AWS-ECS-001, STK-AWS-EKS-002, SEC-AWS-ECR-001, SEC-AWS-VPC-FLOWLOGS-001, STK-AWS-LAMBDA-002/003.
- `fix_disruption: forces_replacement` set where enabling encryption on an existing resource requires replacement (EBS, RDS storage encryption).

### 3. Multi-Framework Compliance (PCI-DSS + SOC2)

`_compliance_gap_report()` now supports three frameworks in addition to CIS.

- New `--compliance-framework [cis|pci_dss|soc2|all]` argument (default: `cis` for backward compatibility).
- Added `pci_dss:` and `soc2_cc:` fields to ~30 catalogue entries spanning IAM, encryption, logging, data retention, and secret management rules.
- PCI-DSS v4.0 controls mapped: Req-1.2, Req-3.4, Req-3.5, Req-3.6, Req-7.1, Req-8.2, Req-10.2.
- SOC2 Trust Services Criteria mapped: CC6.1, CC6.7, CC7.2, CC9.2, A1.2.
- Compliance tab header and OSCAL output updated to display the active framework label.
- Validated in `validate_catalog_entry()` — both fields are optional lists of strings.

### 4. Plan JSON Consumption — Pre-existing

`--plan-json PATH` and `detect_in_plan()` were already fully implemented (Round 14). Documented here for completeness; no new code added. See CI Integration section of SKILL.md for usage.

### 5. Subagent Decomposition for Large Repos (SKILL.md)

Section 1a updated with an explicit file-count threshold table and a full parallel subagent template for all 6 focus areas.

- **< 30 files**: sequential reads in parent.
- **30–100 files**: parallel batched reads (4–6 at a time) in parent.
- **> 100 files + focus:all**: one subagent per focus area (security, robustness, ops, staleness, secrets, drift).
- Standardised subagent output schema: `{file, line, catalogue_id_or_exploratory, excerpt, one_line_justification}`.
- Parent synthesis steps: collect subagent JSON, de-duplicate `(file, line, id)` triples, then run Steps 11–17 (judgement, cost, report) in parent.
- Cross-module (Step 9) and stack-specific (Step 10) checks always run in the parent agent — they require global context unavailable to individual subagents.

### 6. Registry Version Staleness (`--check-registry`)

New opt-in flag that queries `registry.terraform.io` to detect pinned module versions that are significantly behind the latest release.

- `--check-registry`: off by default; opt-in to preserve the stdlib-only, offline-capable contract for normal scans.
- New `_query_registry_latest(namespace, name, provider)` — `urllib.request` GET to the registry API; returns `None` on any network error (never blocks a scan).
- New `_check_module_registry_staleness(all_files_text)` — scans for registry-style module sources, extracts pinned version, emits a finding if behind latest by ≥1 major or ≥3 minor versions.
- New catalogue rule `MOD-STALE-001` (urgency: MEDIUM for major lag, LOW for minor).
- New fixture `fixtures/mod_stale_version/main.tf` (skip-in-self-test — live network unavailable in CI).

### 7. Azure/GCP Attack Graph Edges

`build_attack_graph()` now infers 6 additional edge types covering Azure managed identity, Key Vault, storage account, and SQL Server references, plus two GCP service account binding patterns.

- New patterns: `_EDGE_AZ_MI_RE`, `_EDGE_AZ_KV_RE`, `_EDGE_AZ_STORAGE_RE`, `_EDGE_AZ_SQL_RE`, `_EDGE_GCP_SA_EMAIL_RE`, `_EDGE_GCP_SA_NAME_RE`.
- Expanded `_CROWN_JEWEL_TYPES` with 4 Azure database/messaging types.
- Expanded `_NODE_TYPE_MAP` with ~14 Azure compute, IAM, storage, key, and network resource types.
- Expanded `_is_internet_reachable()` for Azure: `azurerm_public_ip` always reachable; `azurerm_app_service` / `azurerm_linux_web_app` reachable unless `ip_restriction {}` present.

### 8. LLM Calibration for Exploratory Findings (SKILL.md)

Added a "Draft-and-challenge" three-question quality gate that the LLM must apply before including any novel (non-catalogue) finding in the report.

1. **Concrete evidence** — citable file:line required; absence-of-X patterns must be written as catalogue entries, not exploratory findings.
2. **Context sensitivity** — CLAUDE.md / README compensating controls → downgrade to INFO or discard.
3. **Generalisability** — would this pattern fire on a well-configured reference implementation? → likely false positive, discard.

Findings that pass all three are placed in a dedicated **"Exploratory Findings (unverified)"** subsection at the end of the report, clearly labelled as having no stable IDs and not tracked in delta comparisons.

### 9. GitHub Actions PR Comment Fallback

The GitHub Action now posts findings as a collapsible PR comment without requiring Code Scanning (paid/enterprise).

- Added `workflow_dispatch` input `post-pr-comment` (default: `'true'`).
- `detect.py --format markdown` run produces `tf-analyze-summary.md`; JSON run captures finding count.
- SARIF upload step has `continue-on-error: true` — free-tier repos without Code Scanning no longer fail the job.
- New `actions/github-script@v7` step: posts or updates a bot comment with a `<details>` collapsible block on every PR push.

### Infrastructure

- `--compliance-framework` argument added (`cis`/`pci_dss`/`soc2`/`all`).
- `--check-registry` argument added.
- `docs/cli.md` regenerated via `scripts/gen-cli-docs.py`.
- SKILL.md argument-hint frontmatter updated with new flags.

---

## Round 15 — 2026-05-07

**Four new enterprise features (+~550 lines detect.py, fix_disruption on 8 catalogue entries):**

### 1. Fix Centrality Scoring

When `--attack-graph` is active, findings are now ranked by **attack-path impact**: a BFS simulation removes each finding's resource node from the graph and counts how many crown-jewel resources (RDS, S3, KMS, Secrets Manager) become unreachable from the internet. The result is a scored "Fix Priority" ranked table.

- HTML (`--format html --attack-graph`): new **Fix Priority** tab alongside Findings / Attack Graph / Executive View. Table columns: Priority rank, Rule, Resource (with CRITICAL-PATH and INET-REACHABLE badges), Crown Jewels Blocked, Score.
- Text: fix centrality summary printed to stderr (`# fix centrality: top fix is '...'`).
- New function: `_score_fix_centrality(graph, findings) -> list[dict]`.
- New renderer: `_render_fix_priority_html(scored) -> str`.

### 2. Safe-to-Fix Disruption Classification

New `fix_disruption` field (`none` / `plan_required` / `forces_replacement`) and optional `fix_disruption_note` added to 8 catalogue entries with `fix_hcl`. Validated in `validate_catalog_entry()`.

- HTML (`--show-fixes`): coloured badge appears in the "Suggested fix" summary line — green for non-disruptive, amber for plan-required, red for forces-replacement. Disruption note rendered as small italic below the badge.
- Text (`--show-fixes`): disruption level and note printed as `# Fix disruption: ...` comment above the HCL snippet.
- Updated entries: `SEC-AWS-KMS-001` (plan), `SEC-AWS-S3-001` (plan), `SEC-AWS-SG-001` (plan), `ROB-AWS-LIFECYCLE-001` (none), `SEC-AWS-SSRF-001` (forces replacement), `SEC-AWS-IAM-001` (plan), `SEC-AWS-RDS-001` (plan), `INT-INTENT-003` (plan).
- New helpers: `_VALID_FIX_DISRUPTIONS`, `_FIX_DISRUPTION_LABELS`, `_disruption_badge(disruption) -> str`.

### 3. CIS Compliance Gap Report

New `--compliance` flag and `--format compliance` output mode. Maps every finding against CIS benchmark controls declared in catalogue `cis:` fields (70 entries across AWS v3.0, GCP v4.0, Azure v2.0). Reports PASS (no finding fired), FAIL (finding fired), or omits NOT-ASSESSABLE controls.

- `--format compliance`: plain-text table grouped by framework with coverage summary line.
- `--format html --compliance`: new **Compliance** tab with per-framework progress bar + PASS/FAIL table (also works standalone without `--attack-graph`).
- `--oscal PATH`: writes an OSCAL Assessment Results JSON alongside any other format. OSCAL v1.1.2 structure with control findings list.
- New functions: `_infer_cis_framework()`, `_compliance_gap_report()`, `_render_compliance_text()`, `_render_compliance_html()`, `_compliance_to_oscal()`.
- When `--compliance` is used with `--format text`, compliance table is appended after the Mermaid attack graph block.

### 4. GitHub PR Suggestions (`--mode pr-review`)

New `--mode pr-review` that posts findings as inline GitHub PR review comments via the GitHub REST API. Findings with `fix_hcl` are posted as `` ```suggestion ``` `` blocks — reviewers can apply fixes with one click.

- Requires `GITHUB_TOKEN` env var, `--repo OWNER/REPO`, and `--pr-number N`.
- Fetches PR diff to build `{filename: {line: diff_position}}` position map; only findings whose lines appear in the PR diff are posted.
- Review body summarises total finding count; each inline comment includes urgency, recommendation, suggestion block, and disruption level.
- New function: `_pr_review_mode(args, findings, entries) -> None`.
- New argparse flags: `--repo`, `--pr-number`.

### Infrastructure

- `--mode` choices extended: `pr-review` added.
- `--format` choices extended: `compliance` added.
- `docs/cli.md` regenerated via `scripts/gen-cli-docs.py`.

---

## Round 14 — 2026-05-07

**Eight major new features (+~700 lines detect.py, +7 catalogue rules, +7 fixtures, +3 screenshots):**

### 1. Reachability-aware urgency

When `--attack-graph` is active, findings are now dynamically re-tiered by network topology:
- Resources on the BFS critical path (shortest internet→crown-jewel route): urgency promoted one tier (HIGH→CRITICAL, MEDIUM→HIGH, etc.) and tagged with a `CRITICAL-PATH` HTML badge.
- Resources with no inbound path from the INTERNET node: urgency demoted one tier.
- `--fail-on` CI gate uses effective urgency, so a MEDIUM finding on a critical-path resource will trip a `--fail-on HIGH` gate.

New function: `_apply_reachability_urgency(findings, graph, entry_map)`. New helper: `_effective_urgency(f, entry)` used throughout HTML, SARIF, and text output.

### 2. Intent-implementation gap detection (`INT-*`)

New `intent_gap` pattern kind and 4 catalogue rules that catch when Terraform code contradicts its own stated intent:
- `INT-INTENT-001` — variable with security-intent name/description (`prod`, `secure`, `require`, `enforce`, `encrypt`, `tls`, `ssl`, `auth`) that defaults to `false`, `null`, or `0`
- `INT-INTENT-002` — variable description contains "must be true"/"required"/"enforced"/"mandatory" but no `validation {}` block enforces it
- `INT-INTENT-003` — resource tagged `Environment=prod/production` with `deletion_protection=false` (HIGH)
- `INT-INTENT-004` — resource tagged `Environment=prod/production` with `force_destroy=true` (HIGH)

Engine: `intent_gap` dispatch in `detect_corpus()` using 7 new `_INTENT_*` regex constants. Fixtures: `int_intent_var_false_default`, `int_intent_desc_no_validation`, `int_intent_prod_deletion`, `int_intent_prod_force_destroy`.

### 3. Module supply-chain analysis (`MOD-SUPPLY-*`)

3 new catalogue rules using existing `grep` kind:
- `MOD-SUPPLY-001` — module `source` URL contains `?ref=main` or `?ref=master` (mutable git ref, HIGH)
- `MOD-SUPPLY-002` — module using `git::` raw source instead of Terraform Registry (LOW)
- `MOD-SUPPLY-003` — registry-style module source (`namespace/module/provider`) without `version` constraint (HIGH)

Fixtures: `mod_supply_mutable_ref`, `mod_supply_git_source`, `mod_supply_no_version`. No engine changes — pure catalogue additions.

### 4. Generated `terraform test` files (`--gen-tests OUTDIR`)

New CLI flag. Reads optional `test_template` field from catalogue entries, substitutes `{resource}` and `{rule_id}` placeholders, writes `.tftest.hcl` assertion files to OUTDIR. Native Terraform test format (TF ≥ 1.6). `test_template` added to 10 catalogue entries: `SEC-AWS-KMS-001`, `SEC-AWS-S3-001`, `SEC-AWS-SG-001`, `ROB-AWS-LIFECYCLE-001`, `SEC-AWS-RDS-001`, `SEC-GCP-IAM-001`, `SEC-AWS-IAM-001`, `ROB-AWS-RDS-001`, `SEC-AWS-SSRF-001`, `OPS-AWS-TAGS-001`. Validated as optional string in `validate_catalog_entry()`.

### 5. "Attacker's Eye View" Executive HTML tab

When `--attack-graph --format html`, a third "Executive View" tab is added alongside Findings and Attack Graph. Findings are classified into 4 attack stages using graph node membership:
- **Stage 1 — Entry Points**: findings on internet-reachable resources
- **Stage 2 — Lateral Movement**: findings on IAM/network-type resources
- **Stage 3 — Crown Jewels at Risk**: findings on crown-jewel nodes
- **Stage 4 — Blind Spots**: findings in `ops` section (logging/monitoring/tagging) plus unclassified

When a critical path exists, a red-bordered banner identifies the end-to-end attack chain above the stage list. Implemented via `_render_executive_view(findings, entries, graph)`.

### 6. HCL fix suggestions (`--show-fixes`)

New CLI flag. Reads optional `fix_hcl` field from catalogue entries. HTML output: dark-themed `<pre class='fix-hcl'>` block inside a `<details>` disclosure widget inside each finding row. Text output: indented HCL block below the finding line. `fix_hcl` added to 8 catalogue entries: `SEC-AWS-KMS-001`, `SEC-AWS-S3-001`, `SEC-AWS-SG-001`, `ROB-AWS-LIFECYCLE-001`, `SEC-AWS-SSRF-001`, `SEC-AWS-IAM-001`, `SEC-AWS-RDS-001`, `INT-INTENT-003`. Validated as optional string in `validate_catalog_entry()`.

### 7. Fleet mode (`--mode fleet`)

`--target` now accepts multiple values (`action="append"`). `--targets-file FILE` added for file-based target lists. `--mode fleet` scans all targets, cross-correlates findings by `(rule_id, resource, filename)` signature across repos, and reports fleet-wide findings (same misconfiguration in multiple repos) separately from per-repo detail. Output: markdown table (default) or JSON. Implemented via `_fleet_scan()`, `_render_fleet_report()`, `_resolve_fleet_targets()`.

### 8. Risk trend (`--mode trend --lookback N`)

Walks git history without checkout: `git log` enumerates commit SHAs touching `.tf` files; `git show SHA:path` reads historical file content; `detect_in_file()` re-runs the pattern engine at each point. Outputs a per-commit new/resolved/net/total markdown table and summary. `--lookback N` controls window (default 30 days). Implemented via `_trend_get_commits()`, `_trend_tf_files_at_sha()`, `_trend_scan_at_sha()`, `run_trend()`, `_render_trend_table()`. Read-only (never modifies working tree).

**SKILL.md additions:**
- §16f: "New features to use in reports" — guidance for all 8 features in Claude skill mode, including when to recommend `--show-fixes`, `--gen-tests`, fleet scans, and trend reports.

**Documentation:**
- `docs/images/executive-view.png` — screenshot of Executive View tab (46-node AWS corpus).
- `docs/images/show-fixes.png` — screenshot of Findings tab with fix disclosure and three-tab bar.
- `docs/cli.md` regenerated with all new flags documented.
- `README.md`: Output formats section updated with all new flags; Screenshots section updated with two new images; Differentiators expanded from 10 to 17 items.

**Self-test:** 159/159 fixtures passing. Rules: 161 (was 154, +7 new: INT-INTENT-001–004, MOD-SUPPLY-001–003).

---

## Round 13 — 2026-05-06

**New features:**

### Attack-path graph (`--attack-graph`)

`python3 scripts/detect.py --target <dir> --format html --attack-graph --output report.html`

Builds a directed graph from every internet-reachable resource to crown jewels (RDS/Aurora, Cloud SQL, Secrets Manager, KMS keys, S3/GCS buckets, Azure Key Vault/SQL/Storage). Runs BFS to find the shortest path to any crown jewel — the **critical path** — then renders it in two ways:

- **HTML** — second tab in the report with an interactive force-directed SVG. Nodes are pill-shaped, colour-coded by resource category (Compute/IAM/Storage/Secret/Key/Network), with two-line labels (resource name bold on top, type prefix dimmed below). Edges are clipped to pill boundaries so arrowheads land at the node border. Critical-path nodes/edges are red; crown jewels have a gold border. Click any node to open a sidebar showing file, line, and all finding IDs. Drag to reposition. Collision resolution prevents node overlap by computing each pair's minimum separation distance via the ellipse-approximated Minkowski sum of their pill bounding boxes.
- **Text/Markdown** — Mermaid `flowchart LR` block appended after the findings section.

Internet-reachability heuristics: EC2 `associate_public_ip_address`, RDS/Cloud SQL `publicly_accessible`/`ipv4_enabled`, security groups with `0.0.0.0/0` or `::/0` ingress, Cloud Run `INGRESS_TRAFFIC_ALL`, ALB `internet-facing` scheme, GCE `access_config` block, GKE without `private_cluster_config`.

Edge inference from HCL references: `iam_instance_profile`, `role`, `kms_key_id`, `kms_key_name`, `kms_master_key_id`, `secrets_manager_secret_arn`, `vpc_security_group_ids`, GCP service account `email`, GCS `bucket`.

### Adversarial scenario narratives

HIGH and CRITICAL findings in HTML reports gain a bordered italic paragraph citing a confirmed real-world breach that used the same attack vector. 14 rule IDs are covered: `SEC-AWS-SSRF-001`, `SEC-AWS-IAM-001`, `SEC-AWS-IAM-002`, `SEC-GCP-IAM-001`, `SEC-AWS-S3-001`, `SEC-AWS-SG-001`, `SEC-AWS-RDS-001`, `SEC-AWS-CLOUDTRAIL-001`, `SEC-GCP-GKE-NETWORK-POLICY-001`, `SEC-AZURE-RBAC-001`, `SEC-GCP-COMPUTE-PUBLIC-IP-001`, `SEC-AWS-KMS-001`, `SEC-GCP-COMPUTE-SA-001`, `SEC-HARDCODED-SECRET-001`, `SEC-GCP-SQL-PUBLIC-001`. Breaches referenced: Capital One 2019, SolarWinds 2020, Tesla 2020 Kubernetes, Samsung 2022, Twitch 2021, Verizon 2017, Accenture 2017.

In text mode, narratives appear as inline `# ...` comments on each HIGH/CRITICAL finding when `--attack-graph` is active.

### SKILL.md §16e — Adversarial Scenarios (Step 16)

New subsection inside Step 16 (Generate Report) instructs the Claude skill to produce an **Adversarial Scenarios** table for HIGH/CRITICAL findings, using the `_ATTACK_NARRATIVES` dict as templates for the 14 covered rule IDs and generating fresh prose for others. When a `critical_path` is present, a "Critical Attack Path" paragraph precedes the table describing the end-to-end chain in narrative prose.

**New fixture:**
- `fixtures/attack_graph_demo/` — `aws_instance.web` (public IP + IMDSv1) → `aws_security_group.open` (0.0.0.0/0) → IAM profile → role → policy with `resources = ["*"]`, `aws_s3_bucket.data` (no SSE), `aws_kms_key.data_key` (no rotation). Tags on all resources suppress OPS-AWS-TAGS-001.

**Catalogue updates:** `attack_graph_demo` fixture added to `fixtures:` in `CI-TEST-001`, `ROB-AWS-LIFECYCLE-001`, `ROB-AWS-S3-001`, `SEC-AWS-IAM-001`, `SEC-AWS-KMS-001`, `SEC-AWS-S3-001`, `SEC-AWS-S3-LOGGING-001`, `SEC-AWS-S3-PUBLIC-BLOCK-001`, `SEC-AWS-SG-001`, `SEC-AWS-SSRF-001`, `SEC-PROVIDER-001`.

**Layout improvements (follow-up commit):**
- Replaced fixed-radius Coulomb repulsion with pill-aware collision resolution: each tick computes the minimum separation distance for every node pair using the ellipse-approximated Minkowski sum of their pill bounding boxes and applies a restoring force proportional to overlap depth.
- Pill dimensions (`_hw`/`_hh`) are now precomputed before the 400-tick warmup so collision resolution has correct values during the settle phase.
- Replaced random initial placement with type-ordered column layout (Internet → Compute → Network → IAM → Storage → Secret → Key).
- Boundary clamp uses per-node pill half-dims instead of a fixed margin.
- Physics tuning: REP 3500→4000, SL 130→140, SK 0.05→0.04, GV 0.012→0.008, DMP 0.84→0.82.

**Documentation:**
- `docs/images/attack-graph-view.png` — screenshot of the Attack Graph tab (46-node AWS/terragoat corpus).
- `docs/images/findings-narrative.png` — screenshot of a HIGH finding expanded to show the adversarial narrative.
- `docs/images/attack-graph-demo.png` — screenshot of the Findings tab (demo fixture).
- `docs/cli.md` — `--attack-graph` section updated with screenshots and node colour legend.
- `README.md` — Screenshots section added with both images; `--attack-graph` entry in Output Formats; items 9–10 in Differentiators.

**Self-test:** 152/152 fixtures passing. Rules: 154 (unchanged). No corpus changes.

---

## Round 12 — 2026-05-06

**Rules added (+12):**

AWS (8):
- `SEC-AWS-CLOUDFRONT-001` — CloudFront distribution with `viewer_protocol_policy = "allow-all"` (HTTP permitted); `resource_body_contains` on the raw block
- `SEC-AWS-CLOUDFRONT-002` — CloudFront distribution missing `logging_config` block; `resource_missing_arg`
- `SEC-AWS-COGNITO-001` — Cognito user pool MFA disabled or absent; `resource_missing_arg` + `resource_arg regex: 'OFF'`
- `SEC-AWS-SECRETSMANAGER-001` — Secrets Manager secret has no `aws_secretsmanager_secret_rotation` resource; `resource_absent` scope:repo
- `SEC-AWS-APIGW-001` — API Gateway stage missing `access_log_settings` block; `resource_missing_arg`
- `STK-AWS-LAMBDA-002` — Lambda function missing `dead_letter_config` (DLQ); `resource_missing_arg`
- `STK-AWS-LAMBDA-003` — Lambda function missing `tracing_config` (X-Ray); `resource_missing_arg`
- `STK-AWS-ECS-001` — ECS cluster missing `setting` block (container insights disabled); `resource_missing_arg`

GCP (3):
- `SEC-GCP-REDIS-001` — Cloud Memorystore Redis instance with `auth_enabled = false` or missing; `resource_missing_arg` + `resource_arg regex: 'false'`
- `SEC-GCP-REDIS-002` — Cloud Memorystore Redis instance with `transit_encryption_mode = "DISABLED"` or missing; `resource_missing_arg` + `resource_arg regex: 'DISABLED'`
- `STK-GCP-ARTIFACT-001` — Artifact Registry repository missing `kms_key_name` (CMEK); `resource_missing_arg`

Azure (1):
- `SEC-AZURE-VM-001` — Linux VM with `disable_password_authentication = false` or missing (CIS Azure 7.3); `resource_missing_arg` + `resource_arg regex: 'false'`

**Corpus changes:**
- `aws/05_security_misconfiguration.tf` — added `aws_cloudfront_distribution` (allow-all + no logging_config); fires CLOUDFRONT-001/002
- `aws/06_vulnerable_components.tf` — existing Lambda fires STK-AWS-LAMBDA-002/003 automatically (no explicit snippet needed but header comment updated)
- `aws/07_identification_auth.tf` — added `aws_cognito_user_pool` (no mfa_configuration); fires COGNITO-001
- `aws/02_cryptographic_failures.tf` — added `aws_secretsmanager_secret` (no rotation); fires SECRETSMANAGER-001 corpus-level
- `aws/09_logging_monitoring.tf` — added `aws_api_gateway_stage` + `aws_ecs_cluster`; fires APIGW-001/ECS-001
- `gcp/02_cryptographic_failures.tf` — added `google_redis_instance` (auth=false, TLS=DISABLED); fires REDIS-001/002
- `gcp/05_security_misconfiguration.tf` — added `google_artifact_registry_repository` (no kms_key_name); fires ARTIFACT-001
- `azure/07_identification_auth.tf` — added `azurerm_linux_virtual_machine` (disable_password_authentication=false); fires AZURE-VM-001
- `azure/03_injection.tf` — existing `azurerm_linux_virtual_machine.user_data_inject` (no disable_password_authentication) fires AZURE-VM-001 via `resource_missing_arg`

**Fixtures added (+11):** `aws_cloudfront_allow_all`, `aws_cognito_no_mfa`, `aws_secretsmanager_no_rotation`, `aws_apigw_no_access_logs`, `aws_lambda_no_dlq`, `aws_lambda_no_tracing`, `aws_ecs_no_container_insights`, `gcp_redis_no_auth`, `gcp_redis_no_tls`, `gcp_artifact_no_cmek`, `azure_linux_vm_password_auth`

**Documentation:**
- `SKILL.md` — added `resource_arg` match modes section documenting `regex` vs `not_regex` and `block_arg_value` quote-stripping behaviour

**Corpus:** 260 → 274 findings. **Rules:** 142 → 154. **Self-test:** 140 → 151/151.

---

## Round 11 — 2026-05-06

**Rules added (+4):**
- `SEC-GCP-SA-KEY-001` — GCP service account key created in Terraform (static SA keys end up in TF state); `resource_present: google_service_account_key`
- `SEC-GCP-NETWORK-004` — GCP firewall rule exposes database/cache port to 0.0.0.0/0 (`firewall_open_port` for MySQL/PostgreSQL/MSSQL/Redis/MongoDB/Elasticsearch/Memcached)
- `SEC-AWS-S3-LOGGING-001` — S3 bucket missing server access logging (`resource_absent: aws_s3_bucket_logging` when `aws_s3_bucket` present)
- `STK-AWS-EKS-005` — EKS cluster has `enabled_cluster_log_types` but is missing `audit` or `authenticator` log types (uses new `not_regex` field on `resource_arg`)

**Rules extended:**
- `ROB-AWS-RDS-001`, `ROB-AWS-RDS-002`, `ROB-AWS-RDS-003`, `SEC-AWS-RDS-001`, `SEC-AWS-RDS-002` — all 5 RDS rules extended with parallel patterns for `aws_rds_cluster` / `aws_rds_cluster_instance` (Aurora coverage)

**CIS mappings added:**
- 35 AWS/Azure rules updated with CIS mappings: CIS AWS Foundations Benchmark v3.0 (CloudTrail, S3, RDS, KMS, VPC flow logs, SG, EKS, EBS, GuardDuty, IAM) and CIS Azure Foundations Benchmark v2.0 (Key Vault, SQL, RBAC, NSG, Storage, Monitor)

**Engine changes:**
- `not_regex` field added to `resource_arg` pattern kind: fires when attribute is present but its value does NOT match the given regex. Enables partial-config detection (e.g., EKS log types present but missing "audit")
- `hcl_context: true` added to `SEC-SECRETS-001` `.tf` grep patterns: strips HCL comments before matching to prevent false positives on commented-out credential examples
- SARIF `helpUri` base URL corrected from `anthropics/claude-code` to `ChrisAdkin8/tf-analyze`
- SARIF `informationUri` corrected to point at correct repository

**Fixtures added (+4):** `gcp_sa_key`, `gcp_firewall_db_port`, `aws_s3_no_logging`, `aws_eks_partial_logging`

**Corpus:** 252 → 260 findings. **Rules:** 138 → 142. **Self-test:** 136 → 140/140.

---

## Round 10 — 2026-05-06

**Rules added (+8):**
- `SEC-AWS-GUARDDUTY-001` — AWS GuardDuty detector not enabled (resource_absent when aws_vpc present)
- `SEC-AWS-ECR-002` — ECR repository missing image lifecycle policy (resource_absent)
- `SEC-AZURE-MONITOR-001` — Azure subscription missing activity log diagnostic setting (resource_absent)
- `SEC-GCP-COMPUTE-SHIELDED-001` — GCP Compute instance missing shielded_instance_config
- `STK-AWS-LAUNCH-TEMPLATE-001` — EC2 launch template does not enforce IMDSv2 (http_tokens = required)
- `ROB-VERSION-003` — required_providers entry missing version constraint (new engine kind: providers_version_missing)

**Engine changes:**
- `--output PATH` flag: write report to a file instead of stdout (stderr unaffected)
- SARIF `partialFingerprints` now emits two keys: `tfAnalyze/v1` (full file+resource) and `tfAnalyze/v1-resource` (resource-only). GitHub Code Scanning uses the most-specific matching key, so renaming a `.tf` file no longer emits false RESOLVED+NEW pairs for every finding in it.
- New corpus-level pattern kind `providers_version_missing` added to detect.py

**Corpus:** 246 → 252 findings. **Rules:** ~141 → ~149. **Self-test:** 130 → 136/136.

---

## Round 9 — 2026-05-06

**Rules added (+17): AWS/Azure parity with GCP**

AWS (8):
- `ROB-AWS-RDS-003` — RDS instance missing deletion_protection
- `STK-AWS-RDS-004` — RDS EOL engine version (MySQL 5.6, Postgres 9.6–12)
- `ROB-AWS-LIFECYCLE-002` — S3 bucket has force_destroy = true
- `STK-AWS-EKS-001` — EKS endpoint_private_access not enabled
- `STK-AWS-EKS-002` — EKS control plane logging not enabled
- `STK-AWS-EKS-003` — EKS secrets encryption not configured
- `STK-AWS-EKS-004` — EKS OIDC provider absent (no IRSA)
- `STK-AWS-ROUTE53-001` — Route53 zone without DNSSEC key-signing key

Azure (9):
- `STK-AZURE-AKS-003` — AKS workload identity not enabled
- `STK-AZURE-AKS-004` — AKS not a private cluster
- `STK-AZURE-AKS-005` — AKS API server missing authorized IP ranges
- `STK-AZURE-STORAGE-001` — Storage account missing blob versioning
- `SEC-AZURE-SQL-002` — SQL Server firewall rule allows all IPs
- `STK-AZURE-SQL-001` — Deprecated MySQL/PostgreSQL single-server resource
- `SEC-AZURE-KV-003` — Key Vault key missing rotation policy
- `SEC-AZURE-ACR-001` — Container Registry admin account enabled
- `STK-AZURE-DB-001` — MySQL/PostgreSQL server missing SSL enforcement

**Also fixed:** `STK-AWS-LAMBDA-001.yaml` YAML parse error (double-quoted regex with `\.` escape sequences).

**Corpus:** 203 → 246 findings. **Rules:** ~124 → ~141. **Self-test:** 113 → 130/130.

---

## Round 8 — 2026-05-05

**Rules added (+6):**
- `SEC-AZURE-AKS-002` — AKS cluster missing network policy
- `SEC-AZURE-KV-002` — Key Vault missing network ACL deny-by-default
- `SEC-AZURE-WEBAPP-002` — App Service / Function App HTTPS not enforced
- `STK-AZURE-SQL-TDE-001` — Azure SQL Database missing TDE resource (resource_absent)
- `SEC-AWS-CLOUDTRAIL-002` — CloudTrail log file integrity validation disabled
- `STK-GCP-PUBSUB-001` — Pub/Sub topic missing customer-managed encryption key

**Engine changes:**
- Added `suppress_if` field to `resource_missing_arg` pattern kind (static and plan-time handlers). Allows a rule to be suppressed when an alternative attribute provides equivalent security (e.g., SQS `sqs_managed_sse_enabled = true` suppresses the `kms_master_key_id` absence finding).
- Fixed `SEC-AWS-SQS-001` false positive: now suppressed when `sqs_managed_sse_enabled = true`.

**Corpus:** ~192 → 203 findings. **Rules:** ~118 → ~124.

---

## Round 7 — 2026-05-04

**Rules added:** Azure UAMI orphan check (`SEC-AZURE-MI-001`), `graph_check` for UAMI orphan detection, CloudTrail multi-region (`SEC-AWS-CLOUDTRAIL-001`), IMDSv2 enforcement on EC2 (`SEC-AWS-SSRF-001`), and several SQS/SNS/ElastiCache encryption rules.

---

## Round 6 — 2026-05-03

**Rules added:** Azure coverage — RBAC subscription-scope (`SEC-AZURE-RBAC-001`), storage (`SEC-AZURE-STORAGE-001/002`, `ROB-AZURE-STORAGE-001`), Key Vault (`SEC-AZURE-KV-001`, `SEC-AZURE-LOGGING-001`), AKS RBAC (`SEC-AZURE-AKS-001`), SQL AAD admin (`SEC-AZURE-SQL-001`), SQL backup (`ROB-AZURE-SQL-001`), NSG flow logs (`STK-AZURE-NSG-FLOWLOG-001`), NSG open ports (`STK-AZURE-NSG-001`), lifecycle prevent_destroy (`ROB-AZURE-LIFECYCLE-001`), tags (`OPS-AZURE-TAGS-001`), HTTPS-only App Service (`SEC-AZURE-WEBAPP-001`).

---

## Round 1–5 — initial development

Initial skill build: GCP-first catalog (~90 rules), AWS secondary (~15 rules at start), terragoat demo corpus, self-test framework, SARIF/HTML/JSON output, delta tracking, suppression with expiry, `--new-rule` scaffolding, `python-hcl2` fast-path, CI integrations (pre-commit + GitHub Actions).
