# tf-analyze TODO

Priority legend: **P0** = do now · **P1** = next sprint · **P2** = backlog · **P3** = nice-to-have
Complexity: S = 1–2 hrs · M = half day · L = 1–2 days · XL = 3–5 days
Status: `[ ]` not started · `[~]` in progress · `[x]` done

---

## The 8 Priority Items

These are the recommended next actions in implementation order.
Each has a corresponding section in **PLAN.md** with full implementation detail.

### #1 — VS Code Extension: attack graph webview + Marketplace publication
*PLAN.md §1*

- [ ] **P0 · S** Create publisher account at `marketplace.visualstudio.com`
- [ ] **P0 · S** Add 128×128 PNG icon (`vscode-extension/assets/icon.png`); wire into `package.json`
- [ ] **P0 · S** Compile + package: `cd vscode-extension && npm install && npm run compile && npm run package`; confirm `tf-analyze-0.1.0.vsix` builds clean
- [ ] **P0 · S** `vsce publish`; add Marketplace install badge to `README.md`
- [x] **P0 · L** Add attack-graph webview (`vscode-extension/src/attackGraph.ts`): call `detect.py --attack-graph --format json`, render d3.js force-directed graph in a `WebviewPanel` with urgency-coloured nodes, crown-jewel indicators, internet-reachable pulsing borders, click-to-inspect sidebar
- [x] **P1 · S** Wire `tf-analyze.showAttackGraph` command into `package.json` contributes and `extension.ts` activate
- [ ] **P1 · S** Diff-style fix preview: replace code-comment insertion with a `WorkspaceEdit`-based proposed change (accept/reject like Copilot suggestions)
- [ ] **P1 · S** `tf-analyze: Browse rules` command palette entry — fuzzy `QuickPick` over 194 rules by ID + title + urgency
- [ ] **P2 · S** `tf-analyze.ignoreRules` setting — array of rule IDs suppressed project-wide without editing source files
- [ ] **P2 · S** `tf-analyze: Export SARIF` command — write `tf-analyze-findings.sarif` to workspace root

### #2 — Docker image + GHCR publication pipeline
*PLAN.md §2*

- [x] **P0 · S** Write `Dockerfile` at repo root (python:3.12-slim, COPY `scripts/detect.py` + `catalog/`, ENTRYPOINT)
- [x] **P0 · S** Write `.github/workflows/docker.yml`: build + push `ghcr.io/hashicorp/tf-analyze` on semver tags and `main`; multi-arch `linux/amd64` + `linux/arm64`
- [x] **P0 · S** Add `docker run` one-liner to `README.md` Quick Start section
- [ ] **P1 · S** Add `pyproject.toml` with `[project]` metadata so `pip install .` also works
- [ ] **P2 · S** Mirror to Docker Hub as `hashicorp/tf-analyze`

### #3 — GitHub Action: PR suggestion blocks
*PLAN.md §3*

- [x] **P0 · M** Update `integrations/github-action.yml`: post findings as GitHub PR review comments with `suggestion` code blocks using the `fix_hcl` content — reviewers click "Apply suggestion" for 1-click fixes
- [x] **P0 · S** Add `inputs.fail-on` (default `HIGH`) and `inputs.section` (default empty) to the Action so teams tune the gate without forking
- [ ] **P1 · S** Publish Action to GitHub Marketplace (add `action.yml` at repo root with `branding:`)
- [ ] **P1 · S** Add "used by N repos" badge to `README.md` once Action is listed

### #4 — False-positive (clean) fixtures
*PLAN.md §4*

- [x] **P0 · L** Create `fixtures/<RULE-ID>_clean/main.tf` for every rule using `fire_if_absent: true` or `not_regex:` (8 rules: `ROB-AWS-ALB-001`, `SEC-AWS-DOCDB-001`, `SEC-AWS-KINESIS-001`, `SEC-AWS-REDSHIFT-001`, `SEC-AWS-IAM-003`, `SEC-AWS-NEPTUNE-001`, `SEC-AZURE-REDIS-001`, `STK-AWS-EKS-005`)
- [x] **P0 · L** Create `fixtures/<RULE-ID>_clean/main.tf` for all 18 `resource_absent` rules (`ROB-AWS-BACKUP-001`, `SEC-AWS-ECR-002`, `SEC-AWS-GUARDDUTY-001`, `SEC-AWS-S3-LOGGING-001`, `SEC-AWS-SECURITYHUB-001`, `SEC-AWS-S3-PUBLIC-BLOCK-001`, `SEC-AWS-WAF-001`, `SEC-AWS-VPC-FLOWLOGS-001`, `SEC-AZURE-LOGGING-001`, `SEC-AZURE-MONITOR-001`, `SEC-AZURE-SQL-001`, `SEC-GCP-LOGGING-001`, `STK-AWS-EKS-004`, `STK-AWS-ROUTE53-001`, `STK-AZURE-NSG-FLOWLOG-001`, `STK-AZURE-SQL-TDE-001`, `ROB-AWS-SECRETSMANAGER-001`)
- [x] **P0 · M** Add `_run_clean_pass()` to `self_test.py`: scan each `*_clean` fixture directory, assert the rule it corresponds to does NOT fire
- [x] **P0 · M** Add `tests/test_clean_fixtures.py` so the same coverage runs under pytest

### #5 — pytest migration with parallel execution
*PLAN.md §5*

- [x] **P0 · M** Create `pyproject.toml` with `[tool.pytest.ini_options]` (`testpaths = ["tests"]`, `addopts = "-v --tb=short"`)
- [x] **P0 · M** Create `tests/conftest.py` + `tests/helpers.py`: load fixture-case pairs from `fixtures/`
- [x] **P0 · M** Create `tests/test_fixtures.py`: `@pytest.mark.parametrize` over all 192 fixture cases
- [x] **P0 · M** Create `tests/test_clean_fixtures.py`: parametrize over all `*_clean` fixture dirs
- [x] **P0 · L** Create `tests/test_detection_core.py`: unit tests for `block_arg_value()`, `_resolve_var_ref()`, `_extract_var_defaults_by_dir()`, `find_blocks()`, `_expand_dynamic_blocks()`
- [x] **P0 · M** Create `tests/test_attack_graph.py`: unit tests for `build_attack_graph()` with known node/edge fixtures
- [x] **P1 · M** Create `tests/test_output_formats.py`: assert JSON/SARIF/HTML output validity and exit codes  *(Round 25, 17 tests including summary block contract + grade boundaries)*
- [ ] **P1 · S** Add `pytest-xdist` dev dependency; run with `pytest -n auto` in CI
- [ ] **P1 · S** Update `.github/workflows/ci.yml`: replace `python3 scripts/self_test.py` with `pytest --tb=short -q --junitxml=test-results.xml`
- [ ] **P1 · S** Keep `scripts/self_test.py` as thin shim calling pytest for backwards compatibility

### #6 — Custom rules support
*PLAN.md §6*

- [x] **P1 · M** Add `--config PATH` CLI flag to `detect.py` (default: auto-discover `.tf-analyze.yaml` in target dir)
- [x] **P1 · M** Add `_load_project_config(target: Path) -> dict` that reads `.tf-analyze.yaml` and returns `{rules_dir, ignore_rules, thresholds}`
- [x] **P1 · M** Update `load_catalog()` signature to accept optional `extra_rules_dir: Path | None`; merge custom YAML files into catalogue; reserve `CUSTOM-*` ID prefix
- [x] **P1 · M** Apply `ignore_rules` list from project config as project-wide suppressions (after catalogue load, before scan)
- [x] **P1 · S** Add `detect.py --init` command: scaffold `.tf-analyze.yaml` + `.tf-analyze-rules/CUSTOM-EXAMPLE-001.yaml` with commented template
- [x] **P1 · S** Add `tests/test_custom_rules.py`: assert custom YAML rule fires, `ignore_rules` suppresses built-in rule, `CUSTOM-*` IDs rejected
- [ ] **P1 · S** Write `docs/custom-rules.md` with worked example (company-specific tagging rule)

### #7 — LSP server mode (`--lsp`)
*PLAN.md §7*

- [x] **P1 · XL** Add `_run_lsp_server()` to `detect.py`: JSON-RPC server on stdin/stdout; `initialize`, `textDocument/didOpen`, `textDocument/didSave`, `textDocument/didClose`, `textDocument/codeAction`, `shutdown`, `exit`
- [x] **P1 · M** Map urgency to LSP `DiagnosticSeverity`: CRITICAL/HIGH → Error (1), MEDIUM → Warning (2), LOW → Information (3)
- [x] **P1 · M** `textDocument/codeAction` handler: return `WorkspaceEdit` actions inserting `fix_hcl` for findings on the requested range
- [ ] **P1 · S** Update VS Code extension to optionally use `--lsp` instead of spawning `detect.py` per-save (persistent process, lower overhead)
- [x] **P1 · S** Write `docs/lsp.md` with `nvim-lspconfig` stanza and `coc.nvim` example
- [ ] **P2 · S** Add JetBrains LSP client config example

### #8 — Interactive web demo
*PLAN.md §8*

- [x] **P1 · L** Write `demo/app.py` (FastAPI): `POST /scan/hcl` and `POST /scan/repo`, calls `detect.py --format json --attack-graph`, returns findings JSON
- [x] **P1 · L** Write `demo/index.html`: HCL editor (CodeMirror 6), findings table with expandable fix_hcl, d3.js attack-graph SVG
- [x] **P1 · S** Write `demo/Dockerfile` + `demo/fly.toml` for one-command deployment to Fly.io
- [x] **P1 · S** Rate limiting (10 req/min per IP), repo-scan validation (github.com/gitlab.com only), 30s timeout, 50 KB cap
- [ ] **P1 · S** Add "Try the demo" link and badge to `README.md` once deployed
- [ ] **P2 · M** Permalink for scan results: store in SQLite with 24-hour TTL so results are shareable via URL

---

## Backlog

Items beyond the 8 priority recommendations. Implement after the priority items are shipped.

### Detection quality

- [x] **P1 · M** `_extract_local_defaults()` — chase `local.X` references (same pattern as `var.X`)  *(Round 21)*
- [x] **P1 · L** Ternary constant folding: `var.x ? "a" : "b"` where `var.x` has `default = true` → resolves to `"a"`  *(Round 24)*
- [x] **P1 · M** Provider-level `default_tags` awareness — resources that inherit tags via provider don't fail `OPS-AWS-TAGS-001`  *(Round 24)*
- [x] **P1 · M** Module-input flow-through: `module "x" { source = "./c"; foo = bar }` resolves child's `var.foo` to `bar`  *(Round 24)*
- [x] **P1 · XL** `iam_policy_analysis` pattern kind — parse `data "aws_iam_policy_document"` blocks for wildcard actions/resources/public principals  *(Round 24, 6 rules + dedicated fixtures)*
- [ ] **P1 · S** `SEC-AWS-PROVIDER-001` — `skip_credentials_validation = true` in provider block
- [ ] **P1 · S** `SEC-AWS-CONFIG-001/002` — Config recorder + delivery channel absence rules
- [ ] **P1 · S** `SEC-AWS-SHIELD-001` — Shield protection absence for EIP/LB
- [ ] **P1 · S** `SEC-AZURE-DEFENDER-001/002` — Microsoft Defender disabled
- [ ] **P1 · S** `SEC-GCP-BINARY-AUTH-001` — Binary Authorization not enforced on GKE
- [ ] **P1 · M** `SEC-K8S-PSA-001` — Pod Security Admission label missing from namespace
- [ ] **P1 · M** `SEC-K8S-NETPOL-001` — namespace without NetworkPolicy

### Test coverage

- [ ] **P1 · L** `tests/test_apply_fixes.py` — round-trip: copy fixture → apply fixes → re-scan → assert rule resolved
- [ ] **P1 · M** Multi-file fixture: `fixtures/sensitive_module_boundary/` (exercises `SEC-SENSITIVE-002`)
- [ ] **P1 · M** Multi-file fixture: `fixtures/inconsistent_backend_types/` (exercises `ROB-BACKEND-001`)
- [ ] **P1 · M** Catalogue invariant tests in `test_schema.py`: fixture dirs exist on disk, no duplicate IDs, `fix_disruption` is valid enum
- [x] **P2 · S** Performance regression test: 219-fixture corpus scans in < 5s  *(Round 24, `tests/test_perf.py` — current 0.35s)*
- [ ] **P2 · L** `tests/test_fuzz.py` — hypothesis-based scanner robustness tests

### Architecture

- [x] **P1 · M** `--baseline <prior.json>` flag — suppress findings already in prior scan, only new findings affect exit code  *(Round 24)*
- [x] **P1 · L** MITRE ATT&CK mapping: add `mitre:` field to ~50 rules; `--format mitre` output  *(Round 24, 48 rules mapped)*
- [x] **P2 · M** HCP Terraform Run Task server (`integrations/run-task/server.py`)  *(Round 24, FastAPI stub + Dockerfile + docs)*
- [ ] **P2 · M** `--format attestation` — HMAC-signed scan envelope for compliance evidence
- [ ] **P2 · S** OpenTofu compatibility: `applies_when: { runtime: [terraform] }` field on TF-only rules
- [ ] **P2 · M** Atlantis custom workflow integration (`integrations/atlantis/`)
- [ ] **P3 · S** Homebrew formula

### Documentation

- [x] **P1 · S** `docs/custom-rules.md` (after §6)  *(Round 24)*
- [x] **P1 · S** `docs/lsp.md` (after §7)  *(Round 21)*
- [x] **P1 · S** `docs/run-task.md` — HCP Terraform Run Task walkthrough  *(Round 24)*
- [x] **P1 · S** `docs/severity-calibration.md` — methodology log  *(Round 24)*
- [ ] **P2 · S** `docs/mitre-attack.md` — technique reference + coverage matrix
- [ ] **P2 · S** `docs/atlantis.md`
- [ ] **P2 · S** `CONTRIBUTING.md` — "Add a rule in 10 minutes" walkthrough

### Operational / meta

- [ ] **P1 · S** `.github/workflows/release.yml` — GitHub Release on semver tag with `.vsix` artifact
- [ ] **P1 · S** GitHub Actions badges for CI status, rule count, fixture count in `README.md`
- [ ] **P2 · S** `scripts/count-stats.py` — stats summary for badge updates
