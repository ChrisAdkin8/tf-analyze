# tf-analyze TODO

This is the at-a-glance checklist. **[`PLAN.md`](PLAN.md) has the full
detail** for every active item — file paths, test entry-points, why
this now — and is the single document to update when changing scope.
This file is a flat view of the same items so the "what's left?"
question can be answered in 30 seconds without reading prose.

**Priority legend:** `P0` = do now · `P1` = next sprint · `P2` = backlog · `P3` = nice-to-have
**Complexity:** `S` = 1–2 hrs · `M` = half day · `L` = 1–2 days · `XL` = 3–5 days
**Status:** `[ ]` not started · `[~]` in progress · `[x]` done

State at last sync (2026-05-11): **236 rules · 825 tests** + 62 node:test · ext v0.1.47 · R30.10 third audit pass shipped (20 of 22 round-3 findings closed; `_hcl.strip_hcl_context` now preserves newlines inside block comments — fixes the line-counting bug the R30.9 workaround tried but failed to address; `_lsp.py` rejects `*args` callables; `_output.py` urgency rank consolidated to one constant; tests/helpers.run_detect + self_test.py + GitHub Action + terraform-provider compliance + demo/app + badge-service all surface engine crashes with stderr instead of swallowing them) · `detect.py` 4,378 LoC after R30.19 Sessions H–O (-48.1% since modularisation began) · 🌊 Blast Radius tree view + CodeLens + status-bar chip + diagnostic uplift (R30.18; panel wiring fixed in R30.7 / v0.1.44 — `buildArgs()` now passes `--attack-graph`) · `action.yml` posts `--format pr-summary` blocks · `v0.1.0` tagged · per-rule docs site live · Module Reuse Advisor (ROI) · `vscode://` URI handler · status-bar score+grade badge · badge service · MCP server (hardened, R30.0) · Terraform provider · HCP Run Task · GitHub Action · **public web scanner at `tfanalyze.com/scan/<owner>/<repo>` (R30.14)** · **OWASP IaC + NIST CSF + NIST 800-53 + CSA CCM + SLSA + MITRE ATT&CK v17 (69%) + CWE (53%) + D3FEND (40%)** all tagged in catalogue · **13 active `--compliance-framework` modes — all 9 R30.1 modes now surface real data after R30.9 bulk tag** · `--rank-by exploitability` (CISA KEV + FIRST.org EPSS, R30.2) · `--explain-score` top-5 ranking (R30.8) · workflow-YAML walker activates SEC-CICD-001/002/003 (R30.6) · **`--mode drift --state-json` for oncalls (R30.12)** · **`--pdf-output` for CISOs (R30.13)** · **`--apply-fixes × --baseline` + `--mode diff × --baseline` composition (R30.11)** · **`fix_hcl_minimal:` catalogue field (R30.10)** · SARIF v2.1 structured taxonomies + relationships (R30.0.5) · detect.py modularisation: **9 seams shipped** — `_lsp.py` (R30.7); detect.py 8,441 → ~5,170 LoC (−3,271 / **38.7%**) across eight sub-rounds.

---

## Round 30 sprint — OWASP + multi-framework coverage — sub-rounds 0–0.5 ✅ shipped, 1–2 + 6–9 ✅ shipped, 3–5 queued

### Shipped

- [x] **P0 · M** **R30.0** MCP server hardening — LLM01/05/06/10 — *(`_resolve_target` containment in `TFA_REPO_ROOT` + symlink-root rejection + `TFA_MCP_ALLOW_OUTSIDE_ROOT` escape hatch; `<tf-analyze-output>` envelope on every tool with "treat as data" preamble; `MAX_FINDINGS_RETURNED` / `MAX_OUTPUT_BYTES` truncation caps; env-tunable timeouts; 22 tests in `tests/test_mcp_server_hardening.py`)*
- [x] **P1 · S** **R30.0.1** R29 integration cleanup — Run Task `TFA_RUN_TASK_FRAMEWORK` env, TF provider registry docs (`docs/index.md`, `docs/data-sources/scan.md`), compliance-gate worked example, 2 new drift gates in `tests/test_terraform_provider.py`
- [x] **P0 · S** **R30.0.2** GitHub Action sweep — *critical clone-URL fix* (pointed at `anthropics/claude-code-skills`, would have failed on every external user's CI); R28.1 properly wired (`--format pr-summary` is now the comment source); new inputs `compliance-framework` / `attack-graph` / `show-info` / `ref`; 17 drift gates in `tests/test_github_action.py`
- [x] **P1 · S** **R30.0.3** GitHub Pages site coverage — three new pages (`docs/mcp-server.md`, `docs/github-action.md`, `docs/terraform-provider.md`); `docs/index.md` reorganised into Rule reference / Surfaces (10) / Authoring
- [x] **P1 · L** **R30.0.4** MITRE / CWE / D3FEND coverage sweep — 27% → 69% mitre (+91 rules), +114 cwe rules (53%), +87 d3fend rules (40%); ATT&CK pinned to v17 via new `scripts/_mitre.py`; `--format mitre` tactic-grouped + `--mitre-tactic <tactic>` filter; SARIF emits `cwe:` + `d3fend:` tags; per-rule docs render both; 16 tests in `tests/test_mitre_cwe_d3fend.py`; VS Code ext v0.1.30 → v0.1.32
- [x] **P1 · M** **R30.0.5** MITRE round-2 — SARIF v2.1 `taxonomies` + per-rule `relationships` (4 supportedTaxonomies, 131 taxa, 168 rules carry relationships against TerraGoat); D3FEND uses `kinds: ["incomparable"]` so consumers can distinguish "indicates ATT&CK" from "implements D3FEND"; flat tags preserved on properties for backward compat. `--explain` now emits MITRE / CWE / D3FEND lines alongside CIS. New `scripts/check_attack_drift.py` walks the catalogue + verifies every `mitre:` technique exists in `MITRE_TECHNIQUE_INFO`; wired into `.github/workflows/ci.yml`. Extension v0.1.32 → v0.1.33: `bundle-engine.js` drives off `ENGINE_SIBLING_FILES` array + post-bundle smoke test.
- [x] **P1 · S** **R30.0.6** detect.py modularisation Session A — extracted `scripts/_versions.py` (`_version_tuple` + provider-constraint helpers, 204 LoC) and `scripts/_scoring.py` (risk weights + `_compute_summary`, 107 LoC). detect.py shrank 8,441 → 8,214 (-227 LoC). Re-export shims preserve every legacy private name; existing tests untouched and pass. 7 new seam-contract tests in `tests/test_session_a_extracts.py` lock binding-not-copy identity for the re-export. Bundle pipeline: `ENGINE_SIBLING_FILES` array now lists 4 files; `tf-analyze-0.1.34.vsix` ships all four siblings at `engine/scripts/`. Extension v0.1.33 → v0.1.34. Three modularisation seams now shipped — pattern reusable for future extracts of catalog/HCL/attack-graph/render.
- [x] **P1 · L** **R30.0.12 + R30.1 + R30.3 + R30.4 + R30.5** Combined release — Session F refactor (`_cross_resource.py`, 420 LoC) + multi-framework taxonomy schema (5 new optional catalogue fields: `nist_csf`, `nist_800_53`, `csa_ccm`, `slsa`, namespaced `owasp:`) + 9 new `--compliance-framework` modes + 15 new active rules from NSA K8s Hardening, CISA Secure-by-Design, NIST 800-190 (absorbed into SEC-K8S-PSA-001), NIST SSDF, SLSA L2/L3, OWASP CICD Top 10. R30.3 (7 rules: 4 active + 3 stubbed pending workflow-YAML walker), R30.4 (11 rules: 9 active + 2 stubbed pending k8s_manifest walker + cross-account detector), R30.5 (6 enhancements: SEC-K8S-RBAC-001 extended for wildcard verbs / system:authenticated; SEC-K8S-PSA-001 extended for helm runAsNonRoot/readOnlyRootFilesystem/capabilities.drop; new MOD-SUPPLY-004 for `>=` open-upper-bound; new SEC-SECRETS-002 for aws_ssm_parameter plain-String). Also moved `block_arg_value` + `_USE_HCL2` toggle from detect.py into `_hcl.py` so cross-resource detectors import cleanly. 10 new MITRE ATT&CK techniques added to `_mitre.py::MITRE_TECHNIQUE_INFO`. Catalogue 217 → 232 active rules (+15); detect.py 5,528 → 5,116 (−412 LoC); pytest 644 → 658 (+14); self-test 232 → 234 positive fixtures. Extension v0.1.38 → v0.1.39; bundle ships 9 sibling Python files. Deferred (not in this round): SEC-AWS-IAM-POLICY-* confused-deputy extension, SEC-AWS-SSRF-001 + STK-AWS-LAUNCH-TEMPLATE-001 tweak, R30.2 KEV+EPSS exploitability ranking, full bulk taxonomy tagging across pre-existing 217 rules (the new fields are SCHEMA-ready; tagging the legacy catalog is incremental and can land as a follow-on).
- [x] **P1 · L** **R30.0.11** detect.py modularisation Session E — extracted `scripts/_output.py` (**1,619 LoC, largest seam yet**) carrying the entire output-formatter block: 23 names. Canonical URL constants (`RULE_DOCS_URL_BASE`, `SARIF_HELP_URI_BASE`) + 2 data tables (`_ATTACK_NARRATIVES`, `_FIX_DISRUPTION_LABELS`) + 4 SARIF functions (`_sarif_fingerprint`, `_sarif_taxonomies`, `_sarif_rule_relationships`, `to_sarif`) + 4 per-finding helpers + 3 HTML functions (`_render_executive_view`, `_render_fix_priority_html`, `to_html`) + 5 compliance functions + 3 MITRE / PR-summary functions. Three cross-seam edges: `_attack_graph` (`build_attack_graph`, `graph_to_mermaid`, `_render_graph_html`), `_mitre` (`MITRE_ATTACK_VERSION` + `_MITRE_TECHNIQUE_INFO` + `_MITRE_TACTIC_ORDER` underscore-renamed aliases), `_catalog` (`validate_catalog_entry`). Zero engine-state references. detect.py shrank 6,985 → 5,528 (−1,457 LoC). Initial extraction missed the `_MITRE_TECHNIQUE_INFO` / `_MITRE_TACTIC_ORDER` underscore-renamed re-exports; caught by `tests/test_sarif_taxonomies_and_refactor.py::TestMitreModule::test_detect_re_exports_from_mitre` and fixed by adding the alias re-imports back into detect.py's shim. 5 new seam-contract tests in `tests/test_session_e_extracts.py` (module surface, 14-name binding identity, cross-seam edges, SARIF round-trip, PR-summary header lock). Bundle pipeline: `ENGINE_SIBLING_FILES` now lists 8 files; `tf-analyze-0.1.38.vsix` ships all eight siblings; smoke test (now using R30.0.10's `--strict-catalog` enforcement) passing. Extension v0.1.37 → v0.1.38. **Seven modularisation seams shipped** — cumulative detect.py reduction 8,441 → 5,528 (−2,913 LoC / 34.5%) across R30.0.5–R30.0.11; extracted modules total 3,615 LoC. **Monolith below 6k LoC for the first time since Round 12.**
- [x] **P0 · S** **R30.0.10** Bundle smoke test fix — the smoke test's docstring claimed since v0.1.33 to catch "Catalogue YAML parse error introduced in this build" but didn't (only logged the rule count, never asserted it; `--list-rules` silently ignored `--strict-catalog`). Two-part fix: (a) `_cmd_list_rules` in detect.py now accepts + forwards `strict=args.strict_catalog` so the engine exits 2 on any catalogue parse/schema error; (b) `bundle-engine.js` now spawns the engine with `--strict-catalog --list-rules`, asserts a `MIN_RULE_COUNT = 200` floor, and prints a dedicated `CAUSE: catalogue YAML parse OR schema-validation error in this build.` diagnostic when exit 2 stderr mentions catalogue errors. Verified by deliberately corrupting `catalog/CI-TEST-001.yaml`'s `default_urgency` to BOGUS — before: `[bundle-engine] smoke test OK (216 rules)`; after: bundle FAILS with the correct CAUSE line. Pytest unchanged (639); no behavioural delta.
- [x] **P1 · M** **R30.0.9** detect.py modularisation Session D — extracted `scripts/_attack_graph.py` (812 LoC, largest seam yet) carrying the attack-graph build + render block: 2 data constants (`_CROWN_JEWEL_TYPES`, `_NODE_TYPE_MAP`) + 10 `_INET_*` reachability regexes + 15 `_EDGE_*` cross-resource reference regexes + 7 functions (`_is_internet_reachable`, `build_attack_graph`, `_score_fix_centrality`, `_apply_reachability_urgency`, `_mermaid_id`, `graph_to_mermaid`, `_render_graph_html`). Cross-seam edge: `_attack_graph` imports `_URGENCY_TIERS` from `_scoring` — moved out of detect.py in this session because the attack-graph's promote/demote logic needed it. The `_graph_*` detection helpers at the top of the section deliberately stayed in detect.py (they produce findings, a detection concern, not a graph). detect.py shrank 7,669 → 6,985 (−684 LoC). Re-export shims preserve every legacy name (34 total). 5 new seam-contract tests in `tests/test_session_d_extracts.py` (module surface, binding identity, URGENCY_TIERS cross-seam chain, build → mermaid → html round-trip, promote/demote contract). Bundle pipeline: `ENGINE_SIBLING_FILES` now lists 7 files; `tf-analyze-0.1.37.vsix` ships all seven siblings. Extension v0.1.36 → v0.1.37. **Six modularisation seams shipped** — cumulative detect.py reduction 8,441 → 6,985 (−1,456 LoC / 17.2%) across R30.0.5–R30.0.9; extracted modules total 1,996 LoC.
- [x] **P1 · S** **R30.0.8** detect.py modularisation Session C — extracted `scripts/_catalog.py` (443 LoC) carrying the catalogue lifecycle: 6 validation-domain constants (`_VALID_SECTIONS`, `_VALID_URGENCIES`, `_VALID_BLAST_RADIUS`, `_VALID_STATUS`, `_VALID_FIX_DISRUPTIONS`, `_REQUIRED_FIELDS`) + `load_yaml` (minimal stdlib YAML parser, no PyYAML dep) + `validate_catalog_entry` (with CWE / D3FEND / OWASP-IaC shape checks) + `_load_project_config` + `load_catalog`. One cross-seam edge: `_catalog` depends on `_hcl._parse_scalar`. detect.py shrank 7,991 → 7,669 (−322 LoC). Re-export shims preserve every legacy public name (workhorse exports `load_yaml` / `validate_catalog_entry` / `load_catalog` consumed by `test_schema.py`, `test_custom_rules.py`, `gen_rule_docs.py`, `self_test.py`, `check_attack_drift.py`, `stub-status.py`, `tests/helpers.py` — all unchanged). 5 new seam-contract tests in `tests/test_session_c_extracts.py` (binding identity + real-catalog round-trip + typo detection + YAML loader). Bundle pipeline: `ENGINE_SIBLING_FILES` now lists 6 files; `tf-analyze-0.1.36.vsix` ships all six siblings. Extension v0.1.35 → v0.1.36. **Five modularisation seams shipped** — cumulative detect.py reduction 8,441 → 7,669 (−772 LoC across R30.0.5–R30.0.8); extracted modules total 1,184 LoC.
- [x] **P1 · S** **R30.0.7** detect.py modularisation Session B — extracted `scripts/_hcl.py` (320 LoC) carrying the **pure** HCL primitives: `_LINE_COMMENT_RE`, `_BLOCK_COMMENT_RE`, `_DYNAMIC_BLOCK_START_RE` regex constants + `_read_normalized`, `_parse_scalar`, `strip_hcl_context`, `find_blocks`, `find_simple_blocks`, `block_has_arg`, `_hcl_object_to_json`, `block_has_nested_path`, `_expand_dynamic_blocks` functions. State-touching wrappers (`_USE_HCL2`-aware `block_arg_value`, var-resolution layer) intentionally stay in detect.py — the seam is pure-only, same purity criterion as `_versions.py` / `_scoring.py`. detect.py shrank 8,214 → 7,991 (-223 LoC). Re-export shims preserve every legacy name; binding-not-copy identity locked by 5 new seam-contract tests in `tests/test_session_b_extracts.py`. Bundle pipeline: `ENGINE_SIBLING_FILES` now lists 5 files; `tf-analyze-0.1.35.vsix` ships all five siblings; smoke test verified by deliberately removing `_hcl.py` from the array (caught with the right diagnostic). Extension v0.1.34 → v0.1.35. **Four modularisation seams now shipped.** Highest-leverage of the remaining seams — every later extract that touches resource bodies (e.g. `_var_resolve.py`, `_attack_graph.py`, `_catalog.py`) can now depend on these primitives directly instead of poking back into `detect.py`.

### Queued (Phases 1–5)

- [x] **P1 · L** **R30.2** Exploitability prioritisation — `--rank-by {urgency\|exploitability\|hybrid}` flag + `scripts/_threat_intel.py` (CISA KEV + FIRST.org EPSS, daily-cached at `~/.cache/tf-analyze/`, offline-degrades-gracefully). Joins each rule's `cwe:` against KEV's CWE set; promoted findings get a 🔥 KEV badge in text / PR summary / SARIF. `--no-threat-intel` flag for air-gapped CI. 17 tests in `tests/test_threat_intel.py`. *No other OSS IaC scanner integrates KEV today.*
- [x] **P1 · M** **R30.6** Workflow-YAML walker — `_collect_extra_files` walks `.github/workflows/*.yml` + any non-tf `file_glob` declared in the catalogue. `Path.match` replaces broken `lstrip("*/")` suffix check. `not_regex:` field on grep patterns. SEC-CICD-001/002/003 move stub → active. 6 fixtures + 6 walker tests in `tests/test_workflow_walker.py`.
- [x] **P1 · L** **R30.7** detect.py modularisation Session G — `_lsp.py` extracted via callable-injection pattern. detect.py 5,125 → 5,068 LoC. **9th seam.** 11 original LSP tests pass unchanged + 5 new coverage tests + 5 seam-contract tests (`tests/test_session_g_extracts.py`). Bundle ships 10 sibling files (+`_lsp.py`); extension v0.1.39 → v0.1.40.
- [x] **P1 · S** **R30.8** `--explain-score` flag — top-5 score-driving findings ordered by contribution × tier weight, with projected score/grade if each fix is applied. Surfaces: text header block, JSON `score_explanation` field. `scripts/_scoring.py` gains `explain_score()` + `render_score_explanation()`. 9 tests in `tests/test_explain_score.py`.
- [x] **P1 · M** **R30.9** Bulk taxonomy tagging — `scripts/apply_taxonomies.py` tags 174 of 217 legacy rules with NIST CSF 2.0, NIST 800-53 Rev 5, CSA CCM v4, and SLSA. The 9 R30.1 `--compliance-framework` modes now surface real data instead of empty stubs. Bundle ships 11 sibling files (+`_threat_intel.py`).
- [x] **P1 · S** **R30.10** `fix_hcl_minimal:` catalogue field — preferred by `--apply-fixes` when present; falls back to `fix_hcl`. 2 tests.
- [x] **P1 · M** **R30.11** `--apply-fixes × --baseline` and `--mode diff × --baseline` composition — patcher receives only retained findings; diff narrows files and baseline filters tuples. 5 tests in `tests/test_apply_fixes_composition.py`.
- [x] **P1 · M** **R30.12** `tf-analyze drift` — `--mode drift --state-json PATH` re-evaluates the catalogue against `terraform show -json state.tfstate`. Findings tagged `mode='state'`. Reuses plan-mode walker. 6 tests in `tests/test_drift_mode.py`. **New audience (oncalls), near-zero new engine code.**
- [x] **P1 · S** **R30.13** Compliance PDF export — `--pdf-output PATH` via weasyprint (optional dep). 2 tests cover installed + missing branches.
- [x] **P1 · L** **R30.14** Public web scanner — `tfanalyze.com/scan/<owner>/<repo>`. HTML permalink + JSON sibling + per-SHA cache + OG metadata. Dockerfile fixed to ship all 11 engine siblings. fly.toml mounts cache volume. 7 tests in `tests/test_public_scanner.py`. Operator deployment doc at `demo/README.md`. **Load-bearing virality surface.**
- [ ] **P1 · L** **R30.3** New rules — supply-chain / CICD / OIDC (7 rules; +`SEC-CICD-002` from SLSA L2 + `SEC-CICD-003` from SLSA L3 / NIST SSDF on top of original 5) → `PLAN.md§Round-30 R30.3`
- [ ] **P1 · L** **R30.4** New rules — user-data / logging / TLS / throttling / K8s / hygiene (12 rules; +`STK-K8S-IMAGE-SIGNED-001` + `STK-K8S-AUDIT-POLICY-001` from NSA K8s Hardening + `STK-DEFAULTS-001` from CISA Secure-by-Design on top of original 8) → `PLAN.md§Round-30 R30.4`
- [ ] **P1 · L** **R30.5** Enhancements (6) — Confused Deputy / RBAC verbs / helm PSA + container runtime (absorbs NIST 800-190 `STK-K8S-RUNTIME-001` requirement) / ASG-ECS IMDS / `>=` drift / templatefile + SSM → `PLAN.md§Round-30 R30.5`

---

## Round 29 sprint — OWASP IaC Cheat Sheet — ✅ all shipped (2026-05-10)

- [x] **P0 · L** `--compliance-framework owasp_iac` + 49-rule mapping pass + per-rule docs references *(Round 29 — covers 9 cheat-sheet items across 3 sections; renderer auto-sizes for prose labels; 10 tests in `tests/test_compliance_owasp_iac.py`)*
- [x] **P0 · S** `SEC-SENSITIVE-PATTERN-001` HIGH — credential-shaped vars without `sensitive = true` *(Round 29 — suffix-anchored regex; positive + clean fixtures)*
- [x] **P0 · S** `ROB-DRIFT-003` LOW — `ignore_changes` >5 attributes (drift-disable by attrition) *(Round 29 — extends existing `ignore_changes` walker; positive + clean fixtures)*
- [x] **integrations** Compliance picker in VS Code extension v0.1.30; `compliance_report` MCP tool; `compliance_framework` argument on the Terraform provider data source

---

## Round 28 sprint — Top-5 from the deep analysis — ✅ all shipped

The five items from the 2026-05-09 deep analysis that compound *with* publication.

- [x] **P0 · S** `--format pr-summary` flag + Mermaid attack-graph in PR comment summaryBody → `PLAN.md§Round-28 R28.1` *(Round 28 — `_render_pr_summary()`; `action.yml` runs the engine in `pr-summary` mode and uses output verbatim; 14 tests)*
- [x] **P0 · L** Property-based HCL primitive tests (`hypothesis` against `block_arg_value`, `_resolve_var_ref`, `_expand_dynamic_blocks`, `_hcl_object_to_json`) → `PLAN.md§Round-28 R28.2` *(Round 28 — 17 tests; `hypothesis>=6.0` added to dev extras)*
- [x] **P0 · M** LSP server JSON-RPC tests (`tests/test_lsp_server.py`, ~10 cases) → `PLAN.md§Round-28 R28.3` *(Round 28 — 11 tests; subprocess-based to mirror what the extension actually does)*
- [x] **P0 · L** MCP server adapter (`integrations/mcp-server/`, FastAPI/MCP wrapper, 4 tools) → `PLAN.md§Round-28 R28.4` *(Round 28 — `server.py` + `Dockerfile` + `README.md`; tools: scan_workspace / explain_rule / apply_fixes / attack_graph; 14 tests)*
- [x] **P0 · XL** Terraform provider (`terraform-provider-tfanalyze`, Go module, `data "tfanalyze_scan"` v1) → `PLAN.md§Round-28 R28.5` *(Round 28 — Go module under `terraform-provider/`; data source surfaces score/grade/counts/findings_json; `precondition`-gating worked example; 9 cross-validation tests)*

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
- [~] **P1 · L** `detect.py` modularization (split 8,400-LoC monolith — first seam `_mitre.py` shipped in R30.0.5; pattern established for remaining extracts) → `PLAN.md§a.1`
- [ ] **P2 · M** Vendor ATT&CK STIX bundle for richer per-rule docs (R30.0.5-deferred) → `PLAN.md§a.1`
- [ ] **P2 · M** ATT&CK procedure-example linking on per-rule docs pages (depends on STIX bundle) → `PLAN.md§a.1`

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
