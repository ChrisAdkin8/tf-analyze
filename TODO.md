# tf-analyze TODO

This is the at-a-glance checklist. **[`PLAN.md`](PLAN.md) has the full
detail** for every active item — file paths, test entry-points, why
this now — and is the single document to update when changing scope.
This file is a flat view of the same items so the "what's left?"
question can be answered in 30 seconds without reading prose.

**Priority legend:** `P0` = do now · `P1` = next sprint · `P2` = backlog · `P3` = nice-to-have
**Complexity:** `S` = 1–2 hrs · `M` = half day · `L` = 1–2 days · `XL` = 3–5 days
**Status:** `[ ]` not started · `[~]` in progress · `[x]` done

State at last sync (2026-05-09): 215 rules · 500 tests · ext v0.1.29 · `action.yml` shipped · `v0.1.0` tagged · per-rule docs site live · Module Reuse Advisor (ROI) · `vscode://` URI handler with `/scan`, `/explain`, `/suppress` verbs · status-bar score+grade badge · badge service (`integrations/badge-service/`).

---

## Round 28 sprint — Top-5 from the deep analysis

The five items from the 2026-05-09 deep analysis that compound *with* publication.

- [ ] **P0 · S** `--format pr-summary` flag + Mermaid attack-graph in PR comment summaryBody → `PLAN.md§Round-28 R28.1`
- [ ] **P0 · L** Property-based HCL primitive tests (`hypothesis` against `block_arg_value`, `_resolve_var_ref`, `_expand_dynamic_blocks`, `_hcl_object_to_json`) → `PLAN.md§Round-28 R28.2`
- [ ] **P0 · M** LSP server JSON-RPC tests (`tests/test_lsp_server.py`, ~10 cases) → `PLAN.md§Round-28 R28.3`
- [ ] **P0 · L** MCP server adapter (`integrations/mcp-server/`, FastAPI/MCP wrapper, 4 tools) → `PLAN.md§Round-28 R28.4`
- [ ] **P0 · XL** Terraform provider (`terraform-provider-tfanalyze`, Go module, `data "tfanalyze_scan"` v1) → `PLAN.md§Round-28 R28.5`

---

## Active backlog (mirrors PLAN.md)

### a) Skill improvements

#### a.1 Tier 1 — high-leverage, ready now

- [x] **P0 · M** Module Reuse Advisor: ROI signal (lines saved per match) → `PLAN.md§a.1` *(Round 27)*
- [x] **P0 · L** `vscode://` URI handler: `/scan`, `/explain`, `/suppress` verbs → `PLAN.md§a.1` *(Round 27)*
- [x] **P0 · S** SEO: family backlinks on per-rule pages (autogen "See also: `SEC-AWS-IAM-*`") → `PLAN.md§a.1` *(Round 27)*
- [ ] **P1 · S** JSON output `metadata` block (engine SHA, scan timestamp, target path) → `PLAN.md§a.1`
- [ ] **P1 · S** `--explain-score` flag (top-5 score-driving findings) → `PLAN.md§a.1`
- [ ] **P1 · M** `fix_hcl_minimal:` catalogue field for machine-applicable patches → `PLAN.md§a.1`
- [ ] **P1 · M** `--apply-fixes` + `--baseline` composition (skip baselined findings) → `PLAN.md§a.1`
- [ ] **P1 · M** `--mode diff` + `--baseline` composition (narrow to changed files) → `PLAN.md§a.1`
- [ ] **P1 · L** `detect.py` modularization (split 7,500-LoC monolith) → `PLAN.md§a.1`

#### a.2 Tier 2 — moderate leverage

- [ ] **P2 · M** `.tf-analyze-history.json` persistence layer for fix decisions → `PLAN.md§a.2`
- [ ] **P2 · M** `--watch` mode (persistent process, sub-50ms re-scan) → `PLAN.md§a.2`
- [ ] **P2 · M** HCL-formatter pass on inserted `fix_hcl` snippets → `PLAN.md§a.2`
- [ ] **P2 · M** Compliance + trend composition (`--compliance --mode trend`) → `PLAN.md§a.2`
- [ ] **P2 · M** Catalog overlap audit (`scripts/audit_overlap.py`) → `PLAN.md§a.2`
- [ ] **P2 · M** Provider-version `applies_when` annotations sweep → `PLAN.md§a.2`
- [ ] **P2 · L** More K8s + cloud-platform rules (RBAC-002, secret-001, AWS Config/Shield, Azure Defender, GCP Binary Auth) → `PLAN.md§a.2`
- [ ] **P2 · S** Severity calibration round (20 more rules vs tfsec/checkov) → `PLAN.md§a.2`

#### a.3 Tier 3 — long-game

- [ ] **P3 · XL** Tree-sitter HCL parser replacement → `PLAN.md§a.3`
- [ ] **P3 · M** Engine SHA in summary output for drift detection → `PLAN.md§a.3`
- [ ] **P3 · M** Custom rules in bundled-engine extension path → `PLAN.md§a.3`

### b) Test coverage

#### b.1 Tier 1 — risk-driven gaps

- [x] **P0 · S** Module Reuse isolated fixtures (3 `MOD-REUSE-*` rules, 0 fixtures) → `PLAN.md§b.1` *(already shipped: `mod_reuse_*` + `MOD-REUSE-*_clean` wired into both `tests/test_fixtures.py` and `tests/test_clean_fixtures.py`)*
- [x] **P0 · M** URI handler integration tests (`@vscode/test-electron`) → `PLAN.md§b.1` *(Round 27 — `vscode-extension/src/test/uriHandler.test.ts`, 24 `node:test` cases via pure-dispatcher refactor)*
- [x] **P0 · S** JSON-LD validation against Schema.org spec → `PLAN.md§b.1` *(Round 27)*
- [x] **P0 · S** Urgency-tier per-rule pinning (Module Reuse INFO tripwire) → `PLAN.md§b.1` *(Round 27)*
- [ ] **P1 · M** LSP server JSON-RPC tests (200 LoC, 0 tests today) → `PLAN.md§b.1`
- [ ] **P1 · M** HCP Run Task server tests (HMAC-SHA512 path untested) → `PLAN.md§b.1`
- [ ] **P1 · M** `--mode plan` / `--plan-json` tests → `PLAN.md§b.1`
- [ ] **P1 · M** Catalog invariant tests (CIS regex, MITRE regex, regex-compiles, no dup IDs) → `PLAN.md§b.1`
- [ ] **P1 · S** Determinism test (byte-identical JSON across two runs) → `PLAN.md§b.1`
- [ ] **P1 · S** Determinism guard for `gen_rule_docs.py` (no dynamic dates) → `PLAN.md§b.1`
- [ ] **P1 · L** Property-based tests for HCL primitives (`hypothesis`) → `PLAN.md§b.1`

#### b.2 Tier 2 — broaden the safety net

- [ ] **P2 · S** Apply-fixes round-trip extended to nested-path `resource_missing_arg` → `PLAN.md§b.2`
- [ ] **P2 · M** LSP perf budget test (single-file <80ms) → `PLAN.md§b.2`
- [ ] **P2 · M** Web demo (`demo/app.py`) tests → `PLAN.md§b.2`
- [ ] **P2 · L** VS Code extension `@vscode/test-electron` smoke (Quick Fix, attack graph) → `PLAN.md§b.2`
- [ ] **P2 · M** `remediationPanel.test.ts` (most destructive code path, 0 tests) → `PLAN.md§b.2`
- [ ] **P2 · M** Screenshot/landmark regression on docs pages → `PLAN.md§b.2`
- [ ] **P3 · L** Mutation testing (`mutmut`) — quarterly run after modularization → `PLAN.md§b.2`

### c) Virality (engineering)

#### c.1 Tier 1

- [x] **P0 · S** Status-bar score badge with grade colour (`82 (B)` shareable artefact) → `PLAN.md§c.1` *(Round 27)*
- [x] **P0 · M** Live "security score" SVG badge service (`integrations/badge-service/`) → `PLAN.md§c.1` *(Round 27 — FastAPI app + Dockerfile + fly.toml + HMAC-signed `/ingest`; 19 tests)*
- [ ] **P1 · M** Trend output as a graph image (`--format svg` for trend) → `PLAN.md§c.1`

#### c.2 Tier 2

- [ ] **P2 · M** PR comment Mermaid attack-graph snippet → `PLAN.md§c.2`
- [ ] **P2 · S** Hardened-repo demo (`examples/well-formed/`) → `PLAN.md§c.2`
- [ ] **P2 · M** `--format pr-summary` Markdown block → `PLAN.md§c.2`

---

## Operator-only (NOT Claude-executable; see `PLAN.md` Appendix)

### Publication
- [ ] Click "Publish to Marketplace" toggle on v0.1.0 GitHub Release page (one-click; pending four analyses)
- [x] `vsce publish` (VS Code Marketplace) — verified live
- [x] `ovsx publish` (Open VSX) — verified live
- [ ] `flyctl deploy` for `demo/`
- [ ] Register `tf-analyze.dev` (or chosen) domain
- [ ] `./scripts/setup-repo-metadata.sh ChrisAdkin8/tf-analyze` (description + topics via `gh`)

### Marketing / launch
- [ ] Record 30-second LSP-narrative GIF (typing `aws_iam_user`, save, narrative pop, Quick Fix)
- [ ] Record 30-second docs-site → IDE round-trip GIF
- [ ] Embed both GIFs in `README.md` hero
- [ ] "Show HN" post per `docs/launch/hacker-news.md`
- [ ] r/Terraform launch post per `docs/launch/reddit-terraform.md`
- [ ] Pre-commit.com hooks-index PR per `docs/launch/pre-commit-hooks-pr.md`
- [ ] HashiCorp Discuss thread + LinkedIn announcement

### External verification
- [ ] Validate SARIF v2.1 output against the OASIS schema (`sarif-tools` CLI)
- [ ] Manual UX review of compliance HTML in real-world auditor workflow
- [ ] First external-user friction report

---

## Historical record — Rounds 21-26 (mostly shipped)

Preserved here for traceability. Anything not crossed out below has either been superseded by an item in the active backlog above (see PLAN.md cross-references) or is out of scope.

### #1 — VS Code Extension: attack graph webview + Marketplace publication

- [x] **P0 · S** Create publisher account at `marketplace.visualstudio.com` *(operator step; account `tfanalyze` registered, listing live)*
- [x] **P0 · S** Add 128×128 PNG icon (`vscode-extension/assets/icon.png`); wire into `package.json`
- [x] **P0 · S** Compile + package; `tf-analyze-0.1.X.vsix` builds clean (currently v0.1.28)
- [x] **P0 · S** `vsce publish`; Marketplace install badge in `README.md`
- [x] **P0 · L** Attack-graph webview (`vscode-extension/src/attackGraph.ts`)
- [x] **P1 · S** Wire `tf-analyze.showAttackGraph` command
- [x] **P1 · S** Diff-style fix preview (Remediation panel — v0.1.x bulk apply with diff preview)
- [ ] **P1 · S** `tf-analyze: Browse rules` command palette entry — fuzzy `QuickPick` over rules
- [ ] **P2 · S** `tf-analyze.ignoreRules` setting — array of rule IDs suppressed project-wide
- [ ] **P2 · S** `tf-analyze: Export SARIF` command

### #2 — Docker image + GHCR publication pipeline

- [x] **P0 · S** `Dockerfile` at repo root (python:3.12-slim)
- [x] **P0 · S** `.github/workflows/docker.yml`: build + push `ghcr.io/chrisadkin8/tf-analyze` on tags + main; multi-arch
- [x] **P0 · S** Add `docker run` one-liner to `README.md` Quick Start
- [x] **P1 · S** `pyproject.toml` with `[project]` metadata
- [ ] **P2 · S** Mirror to Docker Hub as `chrisadkin8/tf-analyze`

### #3 — GitHub Action: PR suggestion blocks

- [x] **P0 · M** PR review comments with `suggestion` blocks using `fix_hcl`
- [x] **P0 · S** `inputs.fail-on` (default `HIGH`) and `inputs.section`
- [x] **P1 · S** `action.yml` at repo root with `branding:` (engineering shipped; Marketplace toggle pending in operator-only above)
- [ ] **P1 · S** Add "used by N repos" badge once Action is listed

### #4 — False-positive (clean) fixtures

- [x] **P0 · L** `_clean` fixtures for every `fire_if_absent`/`not_regex` rule
- [x] **P0 · L** `_clean` fixtures for all 18 `resource_absent` rules
- [x] **P0 · M** `_run_clean_pass()` in `self_test.py`
- [x] **P0 · M** `tests/test_clean_fixtures.py`

### #5 — pytest migration with parallel execution

- [x] **P0 · M** `pyproject.toml` with `[tool.pytest.ini_options]`
- [x] **P0 · M** `tests/conftest.py` + `tests/helpers.py`
- [x] **P0 · M** `tests/test_fixtures.py` parametrized over fixture cases
- [x] **P0 · M** `tests/test_clean_fixtures.py`
- [x] **P0 · L** `tests/test_detection_core.py`
- [x] **P0 · M** `tests/test_attack_graph.py`
- [x] **P1 · M** `tests/test_output_formats.py` *(Round 25, 17 tests)*
- [ ] **P1 · S** `pytest-xdist` for parallel runs
- [ ] **P1 · S** Replace `self_test.py` with pytest in CI
- [ ] **P1 · S** Keep `scripts/self_test.py` as pytest shim for backwards compat

### #6 — Custom rules support

- [x] **P1 · M** `--config PATH` CLI flag
- [x] **P1 · M** `_load_project_config()` reads `.tf-analyze.yaml`
- [x] **P1 · M** `load_catalog(extra_rules_dir=...)` accepts custom YAML rules; `CUSTOM-*` prefix reserved
- [x] **P1 · M** `ignore_rules` from project config applied as project-wide suppressions
- [x] **P1 · S** `detect.py --init` scaffolds `.tf-analyze.yaml` + sample custom rule
- [x] **P1 · S** `tests/test_custom_rules.py`
- [x] **P1 · S** `docs/custom-rules.md` worked example *(Round 24)*

### #7 — LSP server mode (`--lsp`)

- [x] **P1 · XL** `_run_lsp_server()` with full LSP lifecycle
- [x] **P1 · M** Urgency → `DiagnosticSeverity` mapping
- [x] **P1 · M** `textDocument/codeAction` returns `WorkspaceEdit` with `fix_hcl`
- [x] **P1 · S** Extension uses `--lsp` for real-time diagnostics *(v0.1.14)*
- [x] **P1 · S** `docs/lsp.md` with `nvim-lspconfig` + `coc.nvim` examples
- [ ] **P2 · S** JetBrains LSP client config example

### #8 — Interactive web demo

- [x] **P1 · L** `demo/app.py` (FastAPI) with `/scan/hcl` and `/scan/repo` endpoints
- [x] **P1 · L** `demo/index.html` with CodeMirror 6 + d3 attack graph
- [x] **P1 · S** `demo/Dockerfile` + `demo/fly.toml`
- [x] **P1 · S** Rate limiting + repo-scan validation + 30s timeout + 50 KB cap
- [ ] **P1 · S** "Try the demo" link/badge in `README.md` (operator-blocked: demo not yet deployed)
- [ ] **P2 · M** Permalink for scan results (SQLite, 24-hour TTL)

### Detection quality (Round 21-26)

- [x] **P1 · M** `_extract_local_defaults()` — chase `local.X` references *(Round 21)*
- [x] **P1 · L** Ternary constant folding *(Round 24)*
- [x] **P1 · M** Provider `default_tags` awareness *(Round 24)*
- [x] **P1 · M** Module-input flow-through *(Round 24)*
- [x] **P1 · XL** `iam_policy_analysis` pattern kind *(Round 24, 6 rules)*
- [x] **P1 · M** Inline `aws_iam_policy` JSON analysis (`iam_json_policy_analysis`) *(Round 26, 4 rules)*
- [x] **P1 · M** `SEC-K8S-PSA-001` Pod Security Admission *(Round 26)*
- [x] **P1 · M** `SEC-K8S-NETPOL-001` namespace without NetworkPolicy *(Round 26)*
- [x] **P1 · M** `SEC-K8S-RBAC-001` ClusterRoleBinding to cluster-admin *(Round 26)*
- [x] **P1 · M** `SEC-K8S-HELM-001..002` helm_release LoadBalancer + privileged *(Round 26)*
- [ ] **P1 · S** `SEC-AWS-PROVIDER-001` skip_credentials_validation
- [ ] **P1 · S** `SEC-AWS-CONFIG-001/002` Config recorder + delivery channel *(now in PLAN.md§a.2)*
- [ ] **P1 · S** `SEC-AWS-SHIELD-001` Shield protection absence *(now in PLAN.md§a.2)*
- [ ] **P1 · S** `SEC-AZURE-DEFENDER-001/002` Microsoft Defender disabled *(now in PLAN.md§a.2)*
- [ ] **P1 · S** `SEC-GCP-BINARY-AUTH-001` Binary Authorization *(now in PLAN.md§a.2)*

### Test coverage (Round 21-26)

- [x] **P1 · L** `tests/test_apply_fixes.py` round-trip *(Round 26, 7 tests)*
- [x] **P1 · M** Multi-file fixtures + cross-file resolution *(Round 26)*
- [x] **P2 · S** Performance regression test *(Round 24, `tests/test_perf.py`)*
- [ ] **P1 · M** Multi-file fixture: `fixtures/inconsistent_backend_types/` (`ROB-BACKEND-001`)
- [ ] **P1 · M** Catalogue invariant tests *(now in PLAN.md§b.1, expanded)*
- [ ] **P2 · L** `tests/test_fuzz.py` *(now in PLAN.md§b.1 as property-based tests)*

### Architecture (Round 21-26)

- [x] **P1 · M** `--baseline <prior.json>` flag *(Round 24)*
- [x] **P1 · L** MITRE ATT&CK mapping + `--format mitre` *(Round 24, 48 rules)*
- [x] **P2 · M** HCP Terraform Run Task server *(Round 24)*
- [ ] **P2 · M** `--format attestation` — HMAC-signed scan envelope
- [ ] **P2 · M** Atlantis custom workflow integration (`integrations/atlantis/`)
- [ ] **P3 · S** Homebrew formula

### Documentation (Round 21-26)

- [x] **P1 · S** `docs/custom-rules.md` *(Round 24)*
- [x] **P1 · S** `docs/lsp.md` *(Round 21)*
- [x] **P1 · S** `docs/run-task.md` *(Round 24)*
- [x] **P1 · S** `docs/severity-calibration.md` *(Round 24)*
- [ ] **P2 · S** `docs/mitre-attack.md` — technique reference + coverage matrix
- [ ] **P2 · S** `docs/atlantis.md`
- [ ] **P2 · S** `CONTRIBUTING.md` — "Add a rule in 10 minutes" walkthrough

### Operational / meta (Round 21-26)

- [x] **P1 · S** `.github/workflows/release.yml` — GitHub Release on semver tag *(v0.1.0 work)*
- [x] **P1 · S** GitHub Actions badges (CI status, version, Marketplace, etc.) in `README.md`
- [ ] **P2 · S** `scripts/count-stats.py` — stats summary for badge updates

---

## Sync conventions

When a PLAN.md item changes priority, ships, or is dropped:

1. **Update PLAN.md** with the rationale (why moved/why dropped).
2. **Update the matching row here** (tick the box, add a `*(Round NN)*` annotation, or remove if dropped).
3. **Add a CHANGELOG entry** when the item ships.
4. **Re-run the deep analysis** (search "*how this skill can be improved*") periodically to surface fresh candidates as the project surface grows.
