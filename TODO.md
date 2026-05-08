# tf-analyze TODO

Priority legend: **P0** = blocks other work / immediate viral impact · **P1** = high value, do next sprint · **P2** = medium value, backlog · **P3** = nice-to-have

Complexity: S = 1–2 hrs · M = half day · L = 1–2 days · XL = 3–5 days

Status markers: `[ ]` not started · `[~]` in progress · `[x]` done

---

## 1. Distribution & Virality

### 1.1 VS Code Extension — ship to Marketplace

- [ ] **P0 · M** Add 128×128 PNG icon to `vscode-extension/assets/icon.png`; reference in `package.json`
- [ ] **P0 · S** Create publisher account at `marketplace.visualstudio.com` under `hashicorp` namespace
- [ ] **P0 · S** `cd vscode-extension && npm install && npm run compile && npm run package` → verify `tf-analyze-0.1.0.vsix` builds without errors
- [ ] **P0 · S** `vsce publish` — list on VS Code Marketplace; add install badge to `README.md`
- [ ] **P1 · L** Add attack-graph webview to the extension: embed d3.js SVG inside a `WebviewPanel`; call `detect.py --attack-graph --format json`, parse nodes/edges, render force-directed graph with urgency-coloured nodes. This is the screenshot-worthy feature that drives sharing.
- [ ] **P1 · M** Inline diff-style fix preview: instead of inserting a code comment, show a proposed edit using `vscode.TextEditorDecorationType` with a green/red diff view — accept/reject like Copilot suggestions
- [ ] **P1 · S** Command palette rule search: `tf-analyze: Browse rules` opens a `QuickPick` over all 194 catalogue entries with ID + title + urgency; selecting one opens the webview recommendation panel
- [ ] **P1 · S** Register the extension as a `terraform-ls` diagnostic provider so findings appear alongside the official HashiCorp Terraform extension's output (no duplicate squiggles)
- [ ] **P2 · S** `tf-analyze: Export SARIF` command — write current findings to `tf-analyze-findings.sarif` in the workspace root
- [ ] **P2 · S** Settings UI: add `tf-analyze.ignoreRules` (array of rule IDs) respected as project-level suppressions without editing source files

### 1.2 Docker image

- [ ] **P0 · S** Write `Dockerfile` at repo root:
  ```dockerfile
  FROM python:3.12-slim
  WORKDIR /app
  COPY scripts/detect.py catalog/ ./
  ENTRYPOINT ["python3", "detect.py"]
  ```
- [ ] **P0 · S** Add `.github/workflows/docker.yml`: build + push to `ghcr.io/hashicorp/tf-analyze` on every semver tag and `main`; add multi-arch (`linux/amd64`, `linux/arm64`)
- [ ] **P0 · S** Add `docker run` one-liner to `README.md` and `docs/cli.md`:
  ```bash
  docker run --rm -v $(pwd):/workspace ghcr.io/hashicorp/tf-analyze \
    --target /workspace --format html > report.html
  ```
- [ ] **P1 · S** Publish to Docker Hub as `hashicorp/tf-analyze` for users who prefer Docker Hub over GHCR

### 1.3 GitHub Action — PR suggestion blocks

- [ ] **P0 · M** In `integrations/github-action.yml`, format `fix_hcl` as native GitHub suggestion blocks in PR comments:
  ````markdown
  > [SEC-AWS-EBS-001] EBS volume not encrypted — line 12
  ```suggestion
  resource "aws_ebs_volume" "data" {
    encrypted  = true
    kms_key_id = aws_kms_key.ebs.arn
  ```
  ````
  Reviewers click "Apply suggestion" → fix committed automatically. This is the highest-virality UX moment.
- [ ] **P1 · S** Add `inputs.fail-on` to the Action (default `HIGH`) so teams can tune the gate without forking
- [ ] **P1 · S** Add `inputs.section` filter so teams can gate on security-only without noise from style/ops rules
- [ ] **P2 · S** Publish the Action to GitHub Marketplace (`action.yml` at repo root with `branding:` colour/icon)

### 1.4 Interactive web demo

- [ ] **P1 · L** Build minimal web app (`demo/`): paste HCL or enter a GitHub repo URL → runs `detect.py` server-side → renders findings + attack graph SVG. No signup required.
  - Backend: FastAPI + `subprocess` to call `detect.py --format json`
  - Frontend: single HTML file with d3.js for the attack graph
  - Deploy: Vercel / Railway / Fly.io (one `fly.toml`)
- [ ] **P1 · S** Add "Scan this repo" badge to `README.md` pointing at the demo with a pre-filled GitHub URL
- [ ] **P2 · S** Permalink for scan results (store in Redis with 24-hour TTL) so results are shareable via URL

### 1.5 HCP Terraform Run Task

- [ ] **P1 · L** Write `integrations/run-task/server.py`: a minimal FastAPI webhook server that accepts HCP Terraform run task callbacks, calls `detect.py --plan-json <plan_file> --format json`, and posts back a run task result with findings summary and link to HTML report
- [ ] **P1 · M** Write `integrations/run-task/terraform/` — example HCP Terraform workspace config wiring the run task
- [ ] **P1 · S** Document in `docs/run-task.md` with the three setup steps (deploy server, register with HCP TF, add to workspace)
- [ ] **P2 · S** Apply to list on the HCP Terraform Run Task Registry

### 1.6 Atlantis integration

- [ ] **P2 · M** Write `integrations/atlantis/workflow.yaml` custom Atlantis workflow that runs `detect.py --mode diff` after `plan` and posts findings as a PR comment via the Atlantis comment API
- [ ] **P2 · S** Document in `docs/atlantis.md`

---

## 2. Detection Quality

### 2.1 Variable / local reference resolution improvements

- [ ] **P1 · M** Add `_extract_local_defaults(tf_files)` alongside the existing `_extract_var_defaults_by_dir()` — parse `locals {}` blocks, build a `dict[str, str]` of constant-valued locals (string/bool/number literals only; skip expressions that reference other vars/locals to avoid cycles)
- [ ] **P1 · M** Extend `_resolve_var_ref()` to also chase `local.X` references using the locals map; rename to `_resolve_value_ref()` and update all call sites
- [ ] **P1 · L** Add basic constant-folding for ternary expressions: `var.x ? "a" : "b"` where `var.x` has `default = true` → resolves to `"a"`. Covers the most common pattern (`encrypted = var.encrypt ? true : false`). Implement as a recursive descent over simple HCL expressions — no need for a full parser.
- [ ] **P2 · M** Extend variable-default substitution to `coalesce(var.x, "default")` and `try(var.x, "default")` — both have a deterministic fallback value when `var.x` is unset

### 2.2 Dynamic block false-positive elimination

- [ ] **P1 · M** In `_expand_dynamic_blocks()`, after expanding, emit a `_DYNAMIC_CONDITIONAL` annotation when the `for_each` is a known-false condition (e.g., `for_each = var.encrypt ? [1] : []` with `var.encrypt` defaulting to `true` → block always present). Use this annotation to suppress `resource_missing_arg` false positives on conditionally-emitted blocks.
- [ ] **P2 · L** Full two-pass dynamic block evaluation: first pass collects all `dynamic "X" { for_each = <expr> }` blocks and evaluates the `for_each` condition against variable defaults. If `for_each` evaluates to non-empty, treat the block as statically present for detection purposes.

### 2.3 Provider-level defaults

- [ ] **P1 · M** Parse `provider "aws" { default_tags { tags = {...} } }` blocks and use them to satisfy `OPS-AWS-TAGS-001` / tag-related findings — resources without explicit tags that inherit provider-level tags are not missing tags
- [ ] **P1 · S** Add `SEC-AWS-PROVIDER-001` rule: `provider "aws" { skip_credentials_validation = true }` is a security misconfiguration (skips all credential checks — common in misconfigured CI)
- [ ] **P2 · M** Parse `provider "google" { project = ... region = ... }` and propagate these as implicit attributes on resources that don't set them explicitly (reduces "missing region" false positives)

### 2.4 IAM policy document analysis

- [ ] **P1 · XL** New pattern kind: `iam_policy_analysis` — parse `data "aws_iam_policy_document"` blocks and inspect the statement list for:
  - `actions = ["*"]` with no condition → `SEC-AWS-IAM-004` (wildcard actions)
  - `resources = ["*"]` with `actions` containing write operations → `SEC-AWS-IAM-005`
  - `principals { identifiers = ["*"] }` → `SEC-AWS-IAM-006` (public principal)
  - Effect `Allow` with no `Condition` for cross-account access → `SEC-AWS-IAM-007`
- [ ] **P2 · M** Same analysis for `azurerm_role_definition` and `google_iam_policy` inline JSON blocks

### 2.5 New catalogue rules

**AWS gaps:**
- [ ] **P1 · S** `SEC-AWS-WAF-001b` — `aws_lb` / `aws_alb` with no `aws_wafv2_web_acl_association` (complement to existing WAF rule for CloudFront)
- [ ] **P1 · S** `SEC-AWS-CONFIG-001` — `aws_config_configuration_recorder` absent when `aws_vpc` present (Config must be enabled in accounts with VPCs)
- [ ] **P1 · S** `SEC-AWS-CONFIG-002` — `aws_config_delivery_channel` absent (Config recorder without delivery channel stores nothing)
- [ ] **P1 · S** `SEC-AWS-MACIE-001` — `aws_macie2_account` absent when S3 buckets contain likely-sensitive names (`pii`, `personal`, `customer`, `payment`)
- [ ] **P1 · S** `SEC-AWS-SHIELD-001` — `aws_shield_protection` absent for `aws_eip` / `aws_lb` (Shield Advanced for DDoS protection)
- [ ] **P1 · S** `SEC-AWS-SG-DESCRIPTION-001` — `aws_security_group_rule` or `aws_vpc_security_group_ingress_rule` with no description (un-documented firewall rules)
- [ ] **P2 · M** `SEC-AWS-IAM-004/005/006` — IAM policy document wildcard analysis (see §2.4 above)

**Azure gaps:**
- [ ] **P1 · S** `SEC-AZURE-DEFENDER-001` — `azurerm_security_center_subscription_pricing` absent or `tier = "Free"` (Microsoft Defender disabled)
- [ ] **P1 · S** `SEC-AZURE-DEFENDER-002` — individual Defender plans (VMs, SQL, Storage, Kubernetes, AppServices) not enabled
- [ ] **P1 · S** `SEC-AZURE-POLICY-001` — no `azurerm_policy_assignment` in the corpus (no Azure Policy enforcing org standards)
- [ ] **P2 · S** `SEC-AZURE-PRIVATE-ENDPOINT-001` — `azurerm_storage_account` / `azurerm_key_vault` without `azurerm_private_endpoint` (public endpoint exposure)

**GCP gaps:**
- [ ] **P1 · S** `SEC-GCP-ORG-POLICY-001` — `google_organization_policy` or `google_org_policy_policy` absent (no org-level constraints enforced via Terraform)
- [ ] **P1 · S** `SEC-GCP-VPC-SC-001` — no `google_access_context_manager_service_perimeter` in corpus with GKE clusters (VPC Service Controls not configured)
- [ ] **P1 · S** `SEC-GCP-BINARY-AUTH-001` — `google_container_cluster` without `binary_authorization { evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE" }`
- [ ] **P2 · S** `SEC-GCP-AUDIT-003` — `google_project_iam_audit_config` missing `DATA_READ` / `DATA_WRITE` log types for sensitive services (BigQuery, Storage, KMS)

**Kubernetes depth:**
- [ ] **P1 · M** `SEC-K8S-PSA-001` — namespace without `pod-security.kubernetes.io/enforce: restricted` label (Pod Security Admission not enforced)
- [ ] **P1 · M** `SEC-K8S-NETPOL-001` — `kubernetes_namespace` without a matching `kubernetes_network_policy` (no network segmentation)
- [ ] **P1 · S** `SEC-K8S-SA-AUTOMOUNT-001` — `kubernetes_service_account` with `automount_service_account_token = true` (should be false for most workloads)
- [ ] **P2 · M** `SEC-K8S-IMAGE-DIGEST-001` — container image references without a digest pin (`image: nginx` or `image: nginx:latest` vs `image: nginx@sha256:...`)

---

## 3. Test Coverage

### 3.1 False-positive fixtures (highest ROI)

- [ ] **P0 · L** For every rule with `fire_if_absent: true` or `not_regex:`, create a `fixtures/<rule_id>_clean/main.tf` that the rule must NOT fire on. Add a `clean_pass` in `self_test.py` that asserts zero findings for `*_clean` fixtures.
  
  Rules requiring clean fixtures (non-exhaustive):
  - `SEC-AWS-EBS-001_clean` — EBS volume with `encrypted = true`
  - `SEC-AWS-RDS-002_clean` — RDS with `storage_encrypted = true`
  - `SEC-AWS-S3-PUBLIC-BLOCK-001_clean` — S3 with all 4 public-access flags true
  - `SEC-AWS-CLOUDTRAIL-001_clean` — CloudTrail with `is_multi_region_trail = true`
  - `SEC-AWS-KMS-001_clean` — KMS key with `enable_key_rotation = true`
  - `ROB-AWS-RDS-001_clean` — RDS with `backup_retention_period = 7`
  - `ROB-AWS-RDS-003_clean` — RDS with `deletion_protection = true`
  - `OPS-AWS-TAGS-001_clean` — resource with all required tags
  - (target: clean fixture for every `fire_if_absent` rule = ~60 new fixture directories)

### 3.2 Unit tests for core functions

- [ ] **P0 · L** Create `tests/test_detection_core.py`:
  - `test_block_arg_value_simple_string()`
  - `test_block_arg_value_bool_false()`
  - `test_block_arg_value_nested_block_returns_body()`
  - `test_block_arg_value_heredoc_returns_none()` (until hcl2 fast-path)
  - `test_block_arg_value_absent_returns_none()`
  - `test_resolve_var_ref_known_default()`
  - `test_resolve_var_ref_no_default_returns_original()`
  - `test_resolve_var_ref_non_var_passthrough()`
  - `test_extract_resource_blocks_multiple_resources()`
  - `test_extract_resource_blocks_with_count()`
  - `test_inline_ignore_suppresses_finding()`
  - `test_nested_path_extraction_two_levels()`
  - `test_nested_path_extraction_missing_returns_none()`

- [ ] **P0 · M** Create `tests/test_attack_graph.py`:
  - `test_build_graph_internet_reachable_to_crown_jewel_produces_path()`
  - `test_build_graph_isolated_resources_no_path()`
  - `test_build_graph_azure_mi_edge_detected()`
  - `test_build_graph_gcp_sa_email_edge_detected()`
  - `test_crown_jewel_types_all_present_in_node_map()`

- [ ] **P1 · M** Create `tests/test_output_formats.py`:
  - `test_json_output_is_valid_json()`
  - `test_sarif_output_has_required_fields()` (validate `runs[0].results[*].ruleId`, `locations`)
  - `test_html_output_contains_findings_table()`
  - `test_compliance_output_has_framework_header()`
  - `test_exit_code_1_when_findings_exceed_threshold()`
  - `test_exit_code_0_when_no_findings()`

### 3.3 pytest migration

- [ ] **P1 · M** Add `pyproject.toml` (or `pytest.ini`) at repo root:
  ```toml
  [tool.pytest.ini_options]
  testpaths = ["tests"]
  ```
- [ ] **P1 · M** Convert `self_test.py` into a `pytest` parametrized test: `@pytest.mark.parametrize("fixture_dir,expected_ids", fixture_cases)`. Keep `self_test.py` as a thin shim (`python3 scripts/self_test.py`) calling pytest for backwards compat.
- [ ] **P1 · S** Add `pytest-xdist` for parallel execution: `pytest -n auto` runs all fixtures in parallel (4–8× speedup on multi-core machines)
- [ ] **P1 · S** CI: replace `python3 scripts/self_test.py` with `pytest --tb=short -q` in `.github/workflows/ci.yml`; add JUnit XML output (`--junitxml=test-results.xml`) for GitHub Actions test summary

### 3.4 Catalogue invariant tests (extend `test_schema.py`)

- [ ] **P1 · M** Every active rule's `fixtures:` list — each named fixture directory must exist on disk (`fixtures/<name>/` with at least one `.tf` file)
- [ ] **P1 · S** Every active rule has at least one fixture (no rules with `fixtures: []` unless `status: stub`)
- [ ] **P1 · S** No duplicate `id:` values across all YAML files
- [ ] **P1 · M** `fix_hcl` field (when present) parses as valid HCL using `python-hcl2` if available; otherwise validate it's non-empty and starts with a resource/data/locals/variable/output keyword
- [ ] **P1 · S** `fix_disruption` is one of `{none, plan_required, forces_replacement}` when `fix_hcl` is set
- [ ] **P2 · M** `blast_radius` is one of the 6 documented values
- [ ] **P2 · L** SARIF output validates against the official SARIF JSON Schema (`https://json.schemastore.org/sarif-2.1.0.json`) — download schema, validate in `test_schema.py`

### 3.5 Multi-file fixture corpus

- [ ] **P1 · M** `fixtures/sensitive_module_boundary/` — root module passes sensitive var to child module without `sensitive = true`; exercises `SEC-SENSITIVE-002`
- [ ] **P1 · M** `fixtures/inconsistent_backend_types/` — `envs/prod/main.tf` uses S3 backend, `envs/dev/main.tf` uses GCS; exercises `ROB-BACKEND-001`
- [ ] **P1 · M** `fixtures/cross_module_iam_breadth/` — three-module stack with project-level + resource-level IAM overlap; exercises `SEC-GCP-IAM-003`
- [ ] **P2 · M** `fixtures/multi_provider_alias/` — root declares alias, child module references undeclared alias; exercises `ROB-PROVIDER-ALIAS-001`
- [ ] **P2 · M** `fixtures/large_corpus_100/` — 100-file synthetic corpus for performance regression testing

### 3.6 Fix-application round-trip tests

- [ ] **P1 · L** Create `tests/test_apply_fixes.py`:
  - For each rule with `fix_disruption: none` (safe, no destroy):
    1. Copy fixture to `tmp_path`
    2. Run `detect.py --target tmp_path --format json` → record finding IDs
    3. Run `detect.py --target tmp_path --apply-fixes apply`
    4. Run `detect.py --target tmp_path --format json` again
    5. Assert the originally-fired rule ID is no longer in findings
  - Covers the full remediation loop end-to-end

### 3.7 Performance regression

- [ ] **P2 · S** Add `tests/test_performance.py`:
  ```python
  def test_scan_192_fixtures_under_threshold():
      start = time.time()
      subprocess.run(["python3", "scripts/detect.py", "--target", "fixtures/", "--format", "json"], ...)
      assert time.time() - start < 5.0  # 5s hard ceiling on 192-fixture corpus
  ```
- [ ] **P2 · S** Store baseline scan time in `tests/perf_baseline.json` on first run; subsequent runs fail if >3× baseline

### 3.8 Property-based / fuzz tests

- [ ] **P2 · L** Add `hypothesis` dev dependency; write `tests/test_fuzz.py`:
  - Generate random valid `resource "aws_*" "x" { <attrs> }` HCL blocks
  - Assert scanner never raises an uncaught exception
  - Assert scanner never returns exit code > 1 for valid HCL
  - Assert clean HCL (all required attributes present with correct values) produces zero findings for the corresponding rule
- [ ] **P3 · M** Fuzz the YAML loader: generate random catalogue YAML, assert `load_catalog()` either loads cleanly or raises a structured validation error (never an unhandled exception)

---

## 4. Architectural Improvements

### 4.1 Custom rules support

- [ ] **P1 · L** Support a `.tf-analyze.yaml` project config at the target directory root:
  ```yaml
  rules_dir: .tf-analyze-rules/     # local catalogue YAML files merged with built-in catalogue
  ignore_rules: [STYLE-DESC-001]    # project-wide suppressions
  thresholds:
    password_min_length: 20         # override rule-level hardcoded values
    backup_retention_days: 14
  ```
- [ ] **P1 · M** `load_catalog()` merges rules from `rules_dir` into the main catalogue; `CUSTOM-*` prefix reserved for user-defined IDs; self_test.py skips `CUSTOM-*` fixtures unless present
- [ ] **P1 · S** `detect.py --init` scaffolds a `.tf-analyze.yaml` and a `tf-analyze-rules/` directory with a commented example rule
- [ ] **P1 · S** Document in `docs/custom-rules.md` with a worked example (company-specific tagging standard)

### 4.2 Language Server Protocol server

- [ ] **P1 · XL** `detect.py --lsp` starts a JSON-RPC LSP server on stdin/stdout:
  - `textDocument/didOpen` and `textDocument/didSave` → trigger scan, publish diagnostics
  - `textDocument/codeAction` → return quick-fix code actions for findings with `fix_hcl`
  - `textDocument/hover` → return finding detail on hover over a squiggle
  - Implement using Python's `asyncio` — no external LSP library required for this minimal surface
- [ ] **P1 · S** Update VS Code extension to optionally use the LSP server instead of spawning `detect.py` on each save (lower overhead, persistent process)
- [ ] **P1 · S** Add Neovim config example to `docs/lsp.md` (`nvim-lspconfig` stanza)
- [ ] **P2 · S** Add JetBrains LSP client config example (IntelliJ/PyCharm/GoLand)

### 4.3 Baseline suppression (`--baseline`)

- [ ] **P1 · M** Add `--baseline <prior.json>` flag: load a prior `--format json` scan, suppress any finding whose `(id, file, resource_address)` fingerprint matches a prior finding
  - Exit code: 0 if only baseline findings exist, 1 if net-new findings above threshold
  - Report shows only net-new findings (baseline findings appear in a collapsed "Suppressed (baseline)" section)
- [ ] **P1 · S** Distinguish from existing `--compare`: `--compare` produces a delta report (what changed), `--baseline` changes CI gating behaviour (only new findings block the build)
- [ ] **P1 · S** Add `--save-baseline <path>` to write the current scan as the new baseline
- [ ] **P2 · S** `--auto-baseline` — auto-discover the most recent `tf-analysis-*.json` under `reports/` as the baseline (same pattern as `--auto-compare`)

### 4.4 MITRE ATT&CK mapping

- [ ] **P1 · M** Add optional `mitre_attack: ["T1190", "T1078"]` list field to catalogue YAML schema (validated in `test_schema.py`)
- [ ] **P1 · L** Populate MITRE ATT&CK technique IDs for the ~50 highest-impact rules:
  - `SEC-AWS-SG-001` → `T1190` (Exploit Public-Facing Application)
  - `SEC-AWS-IAM-001/002` → `T1078` (Valid Accounts)
  - `SEC-AWS-EBS-001`, `SEC-AWS-RDS-002` → `T1486` (Data Encrypted for Impact — attacker can read unencrypted data)
  - `SEC-SECRETS-001` → `T1552.001` (Credentials In Files)
  - `SEC-STATE-001` → `T1552.001`
  - `SEC-AWS-CLOUDTRAIL-001/002` → `T1562.002` (Disable Windows Event Logging — equivalent: disable audit trail)
  - (full mapping table in `docs/mitre-attack.md`)
- [ ] **P1 · S** `--format mitre` output: group findings by ATT&CK tactic; show technique IDs and names; suitable for threat model and red team consumption
- [ ] **P2 · S** Include ATT&CK technique IDs in SARIF output as `tags` on each rule

### 4.5 OpenTofu compatibility

- [ ] **P2 · S** Add optional `applies_when: { runtime: [terraform, opentofu] }` field to catalogue YAML
- [ ] **P2 · M** Detect runtime from `required_providers` source hints or `.terraform-version` / `.opentofu-version` files; filter rules accordingly
- [ ] **P2 · S** Tag the 3–5 rules that are Terraform-only (e.g., `SEC-EPHEMERAL-001` — `ephemeral` resource is TF 1.10+, not yet in OpenTofu) with `applies_when: { runtime: [terraform] }`

### 4.6 Attestation output

- [ ] **P3 · M** `--format attestation` — produce a signed JSON envelope:
  ```json
  {
    "scan_timestamp": "2026-05-08T14:32:00Z",
    "catalogue_hash": "sha256:abc123...",
    "target_hash": "sha256:def456...",
    "findings_count": { "CRITICAL": 0, "HIGH": 2, "MEDIUM": 5 },
    "findings_sha256": "sha256:...",
    "hmac": "..."
  }
  ```
  Signed with HMAC-SHA256 using `TF_ANALYZE_ATTESTATION_KEY` env var. CI pipelines can verify freshness before deploying.
- [ ] **P3 · S** Document attestation verification in `docs/attestation.md`

---

## 5. Documentation

- [ ] **P1 · S** `docs/custom-rules.md` — writing user-defined catalogue entries (see §4.1)
- [ ] **P1 · S** `docs/lsp.md` — LSP server setup for Neovim, Emacs, JetBrains (see §4.2)
- [ ] **P1 · S** `docs/run-task.md` — HCP Terraform Run Task setup (see §1.5)
- [ ] **P1 · S** `docs/mitre-attack.md` — full MITRE ATT&CK technique mapping table (see §4.4)
- [ ] **P2 · S** `docs/atlantis.md` — Atlantis custom workflow integration (see §1.6)
- [ ] **P2 · S** `docs/attestation.md` — attestation output and verification (see §4.6)
- [ ] **P1 · S** Update `docs/cli.md` (re-run `python3 scripts/gen-cli-docs.py`) after each flag addition
- [ ] **P2 · S** `CONTRIBUTING.md` — add section "Adding a catalogue rule in 10 minutes" with a step-by-step walkthrough from YAML → fixture → self_test

---

## 6. Operational / Meta

- [ ] **P1 · S** Add `pyproject.toml` with `[project]` metadata so `pip install .` works (enables Docker image and easier distribution)
- [ ] **P1 · S** Add `.github/workflows/release.yml`: on semver tag push, create GitHub Release with auto-generated changelog from `CHANGELOG.md` section matching the tag; attach `.vsix` artifact
- [ ] **P1 · S** Add GitHub Actions badge to `README.md` for CI status, fixture count, and rule count
- [ ] **P2 · S** Add `scripts/count-stats.py` that prints a stats summary (rules, fixtures, fix_hcl coverage, section breakdown) — used in CI to update the README badge numbers
- [ ] **P2 · S** `scripts/gen-mitre-docs.py` — auto-generate `docs/mitre-attack.md` from catalogue YAML `mitre_attack:` fields (same pattern as `gen-cli-docs.py`)
- [ ] **P3 · S** Homebrew formula at `homebrew-tf-analyze/Formula/tf-analyze.rb` — `brew install hashicorp/tf-analyze/tf-analyze` for macOS users

---

## Implementation order recommendation

If implementing sequentially, this order maximises compounding value:

1. **False-positive fixtures** (§3.1) — closes the biggest trust gap before sharing widely
2. **Docker image** (§1.2) — removes install friction for all downstream adoption
3. **VS Code Marketplace** (§1.1 first 3 items) — passive installs start accumulating
4. **Unit tests + pytest migration** (§3.2 + §3.3) — makes future changes safe
5. **PR suggestion blocks** (§1.3) — turns the existing Action into a 1-click-fix tool
6. **Custom rules support** (§4.1) — community can contribute without forking
7. **Attack graph webview in VS Code** (§1.1) — the screenshot-worthy wow moment
8. **HCP Terraform Run Task** (§1.5) — enterprise distribution channel
9. **LSP server** (§4.2) — every editor, one implementation
10. **MITRE ATT&CK mapping** (§4.4) — differentiates in enterprise security programs
