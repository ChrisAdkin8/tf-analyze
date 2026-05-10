# tf-analyze — Implementation Plan

This file consolidates the engineering recommendations from the five
deep analyses in this session (search the chat history for *"how this
skill can be improved"*) into a prioritised backlog **of items Claude
Code can carry out end-to-end**. Operator-only steps (Marketplace
toggles, `vsce publish`, domain registration, screen recording, social
posting) are listed in the **Appendix** for completeness but are not
the subject of this plan.

| File | Role |
|------|------|
| `PLAN.md` *(this file)* | Engineering backlog, prioritised. Drives the next 5–10 sprints. |
| `TODO.md` | Older Round-21 priority items, mostly shipped. Kept for historical context. |
| `CHANGELOG.md` | Per-round and per-version history of what landed. |
| `docs/launch/` | Operator-facing launch checklist + draft launch posts. |

**Priority legend:** `P0` = do now · `P1` = next sprint · `P2` = backlog · `P3` = nice-to-have
**Complexity:** `S` = 1–2 hrs · `M` = half day · `L` = 1–2 days · `XL` = 3–5 days
**Status:** `[ ]` not started · `[~]` in progress · `[x]` done

State of the world at time of writing (2026-05-10): 217 rules · 629 pytest cases + 24 `node:test` cases · extension v0.1.35 · `action.yml` posts `--format pr-summary` blocks (R28.1 actually wired, was claim-only before R30.0.2) · `v0.1.0` tagged · per-rule docs site live with JSON-LD + family backlinks + 4-verb `vscode://` URI handler + OWASP IaC + CWE + D3FEND references · Module Reuse Advisor with ROI signal · status-bar grade badge · **ten surfaces** (all with R29 framework parity; MCP server hardened against agent-side abuse; GitHub Pages site has dedicated pages for all ten surfaces) + four compliance frameworks (CIS, PCI-DSS, SOC 2, OWASP IaC) + three vulnerability/threat taxonomies (MITRE ATT&CK pinned to v17 with 69% coverage, CWE 53%, MITRE D3FEND 40%) — SARIF v2.1 emits proper structured taxonomies + relationships (R30.0.5), CI ATT&CK-drift gate locks the technique table. detect.py modularisation underway: **four seams shipped** (`_mitre.py`, `_versions.py`, `_scoring.py`, `_hcl.py`) reducing detect.py 8,441 → 7,991 LoC across R30.0.5–R30.0.7.

Round 30 is the OWASP-coverage-and-multi-framework sweep. Sub-rounds 0–0.5 ✅ shipped (MCP hardening, R29 cleanup, GitHub Action fix, site coverage, MITRE/CWE/D3FEND, SARIF taxonomies + drift gate). Phases 1–5 queued: a five-field schema sweep (`owasp:` + `nist_csf:` + `nist_800_53:` + `csa_ccm:` + `slsa:`), a KEV+EPSS exploitability-prioritisation engine feature, and 19 new rules + 6 enhancements driven by both OWASP and the new frameworks (NIST CSF 2.0, NIST SP 800-53 Rev 5, NIST SP 800-190, CSA CCM v4, SLSA v1.0, NSA Kubernetes Hardening, CISA Secure-by-Design).

---

## Round 30 — OWASP + multi-framework coverage sweep — sub-rounds 0–0.5 ✅ shipped (2026-05-10)

Eleven-PR sweep. Sub-rounds 0–0.5 closed agent-side abuse on the MCP adapter, brought every integration onto R29 parity, populated the site, added the two new vulnerability/defence taxonomies (CWE + D3FEND) on top of expanded MITRE ATT&CK coverage, and shipped structured SARIF taxonomies + a CI drift gate so the new tagging can't silently rot. Phases 1–5 add four more compliance frameworks plus the OWASP unified field, an exploitability prioritisation feed, and 19 new rules + 6 enhancements.

| # | Item | Status | Acceptance |
|---|------|--------|------------|
| **R30.0** | MCP server hardening — LLM06 containment + LLM01/05 envelope + LLM10 truncation caps | ✅ | `_resolve_target` enforces `TFA_REPO_ROOT` containment with `TFA_MCP_ALLOW_OUTSIDE_ROOT=1` escape hatch; symlinks at workspace root rejected. Every tool wraps its return value (`<tf-analyze-output>` envelope + `_treat_as: data` preamble). `MAX_FINDINGS_RETURNED` (default 500, env `TFA_MCP_MAX_FINDINGS`) and `MAX_OUTPUT_BYTES` (default 1 MB, env `TFA_MCP_MAX_OUTPUT_BYTES`) cap output. Subprocess timeouts env-tunable (`TFA_MCP_TIMEOUT`, `TFA_MCP_APPLY_TIMEOUT`). 22 hardening tests in `tests/test_mcp_server_hardening.py`; `tests/test_mcp_server.py` gets an autouse fixture so its tmp_path tests survive the new containment gate. |
| **R30.0.1** | R29 integration cleanup — Run Task framework, TF provider registry docs, compliance-gate example | ✅ | `TFA_RUN_TASK_FRAMEWORK` env on `integrations/run-task/server.py` closes the R29 gap (engine + MCP + provider had it; run-task didn't). `terraform-provider/docs/{index,data-sources/scan}.md` populates the registry-page surface. `compliance-gate.tf` example shows `compliance_framework` + `compliance_report` driving a `precondition`. 2 new drift gates in `tests/test_terraform_provider.py`. |
| **R30.0.2** | GitHub Action — critical clone-URL fix + R28.1 wiring + R29 parity + R26/R27 inputs | ✅ | **Critical**: pre-fix `action.yml` cloned `anthropics/claude-code-skills` (wrong repo) and would have failed on every external user's CI; now correctly clones `ChrisAdkin8/tf-analyze` with optional `ref` input for tag/SHA pinning. **R28.1**: PR comment is now sourced from engine's `--format pr-summary` (was claim-only — JS rebuilt the table). **R29**: new `compliance-framework` input renders a collapsible `<details>` compliance section in the PR comment when set. **R26/R27**: new `attack-graph` and `show-info` inputs. 17 drift-gate tests in `tests/test_github_action.py` lock down clone URL, pr-summary plumbing, and the engine-flag wiring for every input. |
| **R30.0.3** | GitHub Pages site coverage — three missing surface pages + index nav rework | ✅ | Three new pages on `chrisadkin8.github.io/tf-analyze/` so the "ten surfaces" claim has navigable links to all ten: `docs/mcp-server.md` (tools, wire-up, full Round 30 hardening section + env-var matrix), `docs/github-action.md` (full inputs table including R30.0.2 additions, behaviour breakdown, pinning guidance, R30 clone-URL upgrade callout), `docs/terraform-provider.md` (quickstart + compliance-gate example + schema + build/test). `docs/index.md` reorganised into Rule reference / Surfaces (10 entries) / Authoring. |
| **R30.0.4** | MITRE / CWE / D3FEND coverage sweep — 27% → 69% mitre, +114 cwe, +87 d3fend | ✅ | 91 additional rules tagged with `mitre:` (GCP 1→25, Azure 5→23, robustness 0→17). New `cwe:` field — 114 rules (53% coverage). New `d3fend:` field — 87 rules (40% coverage); no comparable OSS IaC scanner emits D3FEND tags today. ATT&CK pinned to v17 via `scripts/_mitre.py` (single source of truth, first detect.py modularisation seam). New `--mitre-tactic <tactic>` filter; `--format mitre` now groups by ATT&CK tactic with technique names. SARIF emits `cwe:CWE-<n>` + `d3fend:D3-<token>` tags. Per-rule docs render both new blocks; front-matter keywords include lowercase taxonomy IDs. 16 new tests in `tests/test_mitre_cwe_d3fend.py`. VS Code extension v0.1.30 → v0.1.32 (mitrePanel + ruleExplainer renders both taxonomies). |
| **R30.0.5** | MITRE round-2 — SARIF v2.1 taxonomies + relationships, ATT&CK drift CI gate, extension bundle smoke test | ✅ | SARIF output now includes a structured `taxonomies` array (CWE / MITRE-ATT&CK / MITRE-D3FEND / CIS) with proper guid/uri/taxa shapes plus per-rule `relationships` pointing at the specific taxa each rule touches. GitHub Code Scanning consumers can now semantically filter by taxon (`show me everything that touches CWE-732`) instead of parsing flat tag strings. D3FEND uses `kinds: ["incomparable"]` so consumers can distinguish "indicates ATT&CK technique" from "implements D3FEND defence". Concrete shape against TerraGoat: 4 supportedTaxonomies, 131 taxa across them (26 CWE + 25 MITRE + 11 D3FEND + 69 CIS), 168 rules carry relationships arrays. Flat tags preserved on properties for backward compat. `--explain` now emits MITRE / CWE / D3FEND lines alongside CIS (was a gap). New `scripts/check_attack_drift.py` walks the catalogue and verifies every `mitre:` technique appears in `_mitre.py`'s `MITRE_TECHNIQUE_INFO` table — wired into `.github/workflows/ci.yml` as a fresh CI step. Extension v0.1.32 → v0.1.33: `bundle-engine.js` now drives off an `ENGINE_SIBLING_FILES` array + post-bundle smoke test (adding a new helper module is one line; bundle correctness tested at build time). |
| **R30.1** | Multi-framework taxonomy sweep — `owasp:` + `nist_csf:` + `nist_800_53:` + `csa_ccm:` + `slsa:` | 🟡 queued | **Single schema change unlocks 8 new compliance modes plus 5 OWASP sub-modes auto-derived from `owasp:` prefixes.** Five new optional catalogue fields, all validated by `validate_catalog_entry` against per-field regex (e.g. `nist_csf:` matches `^(GV\|ID\|PR\|DE\|RS\|RC)\.[A-Z]{2}-\d+$`, `slsa:` matches `^(L[1-4]\|source\|build\|deps)$`). Single `_compliance_gap_report` dispatch pattern across all five. New `--compliance-framework` modes: `nist_csf`, `nist_800_53`, `csa_ccm`, `slsa`, `owasp_asvs`, `owasp_top10`, `owasp_cicd`, `owasp_llm`, `owasp_k8s`. The `owasp:` field uses prefix-namespacing (`A01`–`A10`, `API1`–`API10`, `CICD-SEC-1`–`-10`, `LLM01`–`LLM10`, `K01`–`K10`, `ASVS-V<x>.<y>.<z>`). Existing `owasp_iac:` (Round 29) stays untouched. Bulk catalogue tagging via `scripts/apply_taxonomies.py` (manifest-driven, idempotent — same pattern as `apply_mitre.py`); first-pass coverage estimates: nist_csf ~100 rules, nist_800_53 ~100 rules, csa_ccm ~120 rules, slsa ~30 rules. |
| **R30.2** | Exploitability prioritisation — `--rank-by exploitability` (CISA KEV + FIRST.org EPSS) | 🟡 queued | New module `scripts/_threat_intel.py` fetches CISA KEV catalogue (`known_exploited_vulnerabilities.json`) + FIRST.org EPSS scores, cached at `~/.cache/tf-analyze/`, refreshed daily, offline-degrades-gracefully fallback. New CLI flag `--rank-by {urgency\|exploitability\|hybrid}` (default `urgency` — no behaviour change). For findings whose `mitre:` includes a CVE-tied technique (or which include a CVE directly), promote one urgency tier when in KEV; rank by EPSS within tier. New `🔥 KEV` badge in PR summary, VS Code panel, SARIF tags. ~300 lines engine + ~10 tests. **No comparable OSS IaC scanner integrates KEV today** — gives the comparison table a new line. |
| **R30.3** | New rules — supply-chain / CICD / OIDC (7 rules — was 5; +SEC-CICD-002 / SEC-CICD-003 from SLSA + NIST SSDF) | 🟡 queued | `SEC-SUPPLY-001` (artifact integrity / module digest pinning, OWASP CICD-SEC-1/9), `SEC-CICD-001` (required reviewers + OIDC trust on apply, OWASP CICD-SEC-1/3), `SEC-CICD-002` (**SLSA L2** — workflow `permissions:` block must declare minimum scopes; reject `permissions: write-all` / missing block), `SEC-CICD-003` (**SLSA L3 / NIST SSDF** — `apply` job protected by GitHub `environment:` with `required_reviewers`), `SEC-PROVISIONER-002` (curl \| bash detection on local-exec, OWASP CICD-SEC-4), `SEC-DATASOURCE-003` (`data "external"` / `data "http"` plan-time exec, OWASP CICD-SEC-4), `SEC-AWS-IAM-OIDC-001` (GitHub-OIDC trust policy with `repo:*` / wildcard sub, OWASP CICD-SEC-6 + API2). |
| **R30.4** | New rules — user-data, logging, TLS, throttling, K8s, hygiene (12 rules — was 8; +STK-K8S-IMAGE-SIGNED-001 / STK-K8S-AUDIT-POLICY-001 / STK-DEFAULTS-001 from NSA K8s + CISA Secure-by-Design) | 🟡 queued | `SEC-USERDATA-001` (templated secrets + `curl \| bash` in user_data), `SEC-USERDATA-002` (unencoded interpolation of sensitive vars), `SEC-AWS-LOG-RETENTION-001` (object-lock + retention ≥ 90d, CIS 3.x), `SEC-LOG-CROSS-ACCOUNT-001` (log destination in separate account), `SEC-AWS-LB-LISTENER-002` (TLS-1.2+ floor, OWASP A02), `SEC-AWS-APIGW-002` (API-Gateway throttling > 0, OWASP API4), `SEC-AWS-WAF-002` (WAF rate-based rule attached, OWASP API4/6), `STK-K8S-VERSION-001` (control-plane older than k8s N-2, OWASP A06), `STK-K8S-IMAGE-SIGNED-001` (**NSA K8s Hardening** — pod images come from a signed registry / cosign / Notation), `STK-K8S-AUDIT-POLICY-001` (**NSA K8s Hardening** — `aws_eks_cluster.enabled_cluster_log_types` / GKE audit-log config / AKS `oms_agent` block presence), `STK-DEFAULTS-001` (**CISA Secure-by-Design** — `terraform { required_version, required_providers }` block existence + version pin). |
| **R30.5** | Enhancements — Confused Deputy / RBAC verbs / helm PSA + container runtime / ASG-ECS IMDS / `>=` drift / templatefile + SSM | 🟡 queued | Extensions to `SEC-AWS-IAM-POLICY-*` (cross-account `sts:AssumeRole` without `sts:ExternalId`/`aws:SourceAccount`), `SEC-K8S-RBAC-001` (wildcard verbs, `bind`/`escalate`, `system:authenticated`), `SEC-K8S-PSA-001` (helm_release values for `runAsNonRoot` / `readOnlyRootFilesystem` / `capabilities.drop` — absorbs the **NIST 800-190** `STK-K8S-RUNTIME-001` requirement), `SEC-AWS-SSRF-001` + `STK-AWS-LAUNCH-TEMPLATE-001` (ASG `instance_refresh` + ECS `task_role_arn`), `MOD-SUPPLY-001/002/003` (`>=` open-upper-bound flagged, OWASP CICD-SEC-3), `SEC-SECRETS-001` + `SEC-SENSITIVE-*` (`templatefile()` + `aws_ssm_parameter` non-`SecureString`). |

State after R30.0 → R30.0.5 ship: 217 rules · 617 pytest + 24 `node:test` · ten surfaces all hardened/coherent · seven taxonomies tagged in catalogue (CIS, PCI-DSS, SOC 2, OWASP IaC, MITRE ATT&CK v17, CWE, MITRE D3FEND) · SARIF v2.1 taxonomies + relationships emitted · ATT&CK-drift CI gate locks the technique table.

Projected state after R30.1–R30.5 ship: 236 rules (217 + 19) · ~700 pytest · **13 active compliance modes** (4 existing + `nist_csf` + `nist_800_53` + `csa_ccm` + `slsa` + 5 OWASP sub-modes auto-derived) · seven taxonomies plus exploitability prioritisation via `--rank-by exploitability` (KEV+EPSS) — no other OSS IaC scanner integrates KEV today.

---

## Round 29 — OWASP IaC Cheat Sheet compliance + 2 new rules — ✅ shipped (2026-05-10)

Three highest-leverage items from the [OWASP IaC Security Cheat Sheet analysis](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html). Acceptance below; full details in `CHANGELOG.md`.

| # | Item | Status | Acceptance |
|---|------|--------|------------|
| **R29.1** | `--compliance-framework owasp_iac` framework mapping | ✅ | 49 catalogue rules carry `owasp_iac:` mappings across 9 cheat-sheet items in 3 sections (Develop and Distribute / Deploy / Runtime). Per-rule docs surface the references; compliance text/HTML/OSCAL output all carry the new framework. VS Code extension picker adds `OWASP IaC`. MCP server gains a `compliance_report` tool. Terraform provider gains `compliance_framework` input + `compliance_report` output. |
| **R29.2** | `SEC-SENSITIVE-PATTERN-001` (HIGH) | ✅ | Credential-shaped variable suffixes (`_password`, `_token`, `_secret`, `_apikey`, etc.) without `sensitive = true` fire HIGH. Suffix-anchored regex avoids false-positives on identifier-shaped names (`kms_key_arn`, `secret_id`). |
| **R29.3** | `ROB-DRIFT-003` (LOW) | ✅ | `lifecycle.ignore_changes` lists >5 specific attributes — drift-disable-by-attrition. ROB-DRIFT-001 owns `all`; ROB-DRIFT-002 owns wildcard / `[tags]`; this catches the slow-bleed third leg. LOW because legitimate uses exist. |

---

## Round 28 — Top-5 sprint (2026-05-09 deep analysis) — ✅ shipped

All five items closed in a single sprint. Acceptance verified by the test deltas in the table.

| # | Item | Status | Acceptance |
|---|------|--------|------------|
| **R28.1** | `--format pr-summary` + Mermaid attack-graph in the PR comment | ✅ | `scripts/detect.py:_render_pr_summary()` + `action.yml` runs the engine in `pr-summary` mode and uses the pre-rendered Markdown directly. 14 tests in `tests/test_pr_summary.py`. |
| **R28.2** | Property-based HCL primitive tests (`hypothesis`) | ✅ | `tests/test_hcl_primitives.py` — 17 cases covering `_hcl_object_to_json`, `block_arg_value`, `_resolve_var_ref`, `_expand_dynamic_blocks`, `find_blocks`. Each must NEVER raise on arbitrary input. `hypothesis>=6.0` added to `pyproject.toml` dev extras. |
| **R28.3** | LSP server JSON-RPC tests | ✅ | `tests/test_lsp_server.py` — 11 cases via subprocess JSON-RPC: lifecycle, diagnostics, code actions, robustness, unknown-method handling. The 200-LoC `_run_lsp_server` is no longer untested. |
| **R28.4** | MCP server adapter | ✅ | `integrations/mcp-server/{server.py,Dockerfile,requirements.txt,README.md}` + 14 tests in `tests/test_mcp_server.py`. Four tools (`scan_workspace`, `explain_rule`, `apply_fixes`, `attack_graph`) + `tfanalyze://catalogue` resource. `--health` subcommand. Wire-up docs for Claude Desktop / Cursor / Continue.dev. |
| **R28.5** | Terraform provider (v1 data source) | ✅ | `terraform-provider/` Go module — `data "tfanalyze_scan"` returning score/grade/counts/findings_json/json_report. Builds clean with `go build`; `go test ./...` passes. 9 cross-validation tests in `tests/test_terraform_provider.py` (repo shape + Go build + binary boots). Worked example with `precondition`-gated `null_resource`. |

State after Round 28 ships: 215 rules · 565 pytest + 24 `node:test` (was 500+24) · **ten surfaces** (Claude skill, CLI, GitHub Action, Docker, pre-commit, LSP, VS Code extension, HCP Run Task, MCP server, Terraform provider) · PR-comment surface complete · LSP + HCL primitives no longer untested.

---

## a) Skill improvements

### a.1 Tier 1 — high-leverage engineering, ready now

- [x] **P0 · M — Module Reuse Advisor: ROI signal.** *(Round 27 — `_module_reuse_roi()` in `detect.py`, `roi` field on the finding, ROI summary + per-row badge in `moduleReusePanel.ts`. `tests/test_module_reuse.py` includes the PLAN.md acceptance: 200-line VPC reports ≥ 150 lines saved.)* The 3 `MOD-REUSE-*` rules emit "your cluster matches `terraform-aws-modules/vpc/aws`" but no actionable number. Without "you'd save N lines / cut maintenance overhead by X%" no one acts. Count resources in the matched cluster, multiply by lines/resource (use AST line spans from the existing block parser), compare against the ~12-line module call. Render in the finding's `details` field and the panel's match-summary.
  - Files: `scripts/detect.py` (extend the `_module_reuse_*` graph check), `vscode-extension/src/moduleReusePanel.ts` (render the new field).
  - Tests: `tests/test_module_reuse.py` (NEW) — fixture with a 200-line VPC asserts savings ≥ 150 lines.

- [x] **P0 · L — `vscode://` URI handler: extend the verb space.** *(Round 27 — `/scan`, `/explain`, `/suppress` shipped behind strict validators. `/suppress` accepts both per-finding (id+file+line) and workspace-wide (id-only, writes to `.tf-analyze.yaml`'s `ignore_rules:`). Routing extracted into a pure dispatcher (`vscode-extension/src/uriHandler.ts`) with 24 `node:test` cases. Docs site adds a "📝 Suppress in workspace" button next to "📂 Open in VS Code".)* Today the only verb is `/rule/<RULE-ID>` (rule explainer). Add:
  - `vscode://tfanalyze.tf-analyze/scan?target=<path>` — kick off a scan from a docs-site button
  - `vscode://tfanalyze.tf-analyze/explain?id=<RULE-ID>&file=<path>&line=<n>` — open at the offending location
  - `vscode://tfanalyze.tf-analyze/suppress?id=<RULE-ID>&file=<path>&line=<n>` — one-click baseline-add from a PR comment

  Each gets a strict regex validator like the existing `/rule/` route (the v0.1.27 security pattern).
  - Files: `vscode-extension/src/extension.ts` (`registerUriHandler`), `vscode-extension/src/test/uriHandler.test.ts` (NEW).
  - Engine: nothing — these are extension-only.
  - Docs site: `scripts/gen_rule_docs.py` adds a "📝 Suppress in workspace" button next to "📂 Open in VS Code".

- [x] **P0 · S — SEO: family backlinks on per-rule pages.** *(Round 27 — `_family_section()` in `gen_rule_docs.py` groups by `<id-minus-trailing-numeric>` so `SEC-AWS-IAM-001` lists `SEC-AWS-IAM-002`/`-003`. Singleton families render no section. Locked by `tests/test_rule_docs.py::TestSEOAndDeepLinks::test_family_backlinks_present`.)* Each rule page is a leaf today. Adding a "See also: every other `SEC-AWS-IAM-*`" autogenerated section trebles internal links per page → meaningful PageRank lift across the whole subtree. Generator only; engine untouched.
  - Files: `scripts/gen_rule_docs.py` (`render_rule_md` adds a "Family" section after "Related rules"; group by id-prefix-up-to-2nd-hyphen). `tests/test_rule_docs.py::TestSEOAndDeepLinks::test_family_backlinks_present` (NEW).

- [ ] **P1 · S — JSON output: `metadata` block.** Scan timestamp, engine SHA (from `git rev-parse HEAD`), catalogue rev, target path, hostname (optional). Every audit-trail consumer wants this. ~30 lines.
  - Files: `scripts/detect.py` (`_compute_metadata()` + add to `output_data` in both JSON code paths). Test: `tests/test_output_formats.py::TestMetadata` (NEW, ~5 tests).

- [ ] **P1 · S — `--explain-score` flag.** Score is read-only today. Print the 5 highest-weighted findings driving the current score, with the points each contributed. Useful for humans triaging "we scored 62 (C) — what should we fix to get to B?"
  - Files: `scripts/detect.py` (`_explain_score()` after `_compute_summary()`). `tests/test_output_formats.py::TestExplainScore` (NEW).

- [ ] **P1 · M — `fix_hcl_minimal:` catalogue field.** Round 26 round-trip tests proved many `fix_hcl` snippets can't be machine-applied (whole-resource shapes vs. attribute-insertion shapes). Add an optional `fix_hcl_minimal:` to the catalogue schema; `--apply-fixes` prefers it when present, falls back to today's behaviour. Promotes ~50 rules from "documented fix" to "one-click-applicable fix".
  - Files: `scripts/detect.py` (schema validator + `_handle_apply_fixes`), `catalog/*.yaml` (annotate the easy 50). Tests: extend `tests/test_apply_fixes.py::ROUNDTRIP_CASES`.

- [ ] **P1 · M — `--apply-fixes` + `--baseline` composition.** Bulk-remediation should skip findings already in the baseline (user has consciously accepted them). Subtle but real source of "the AI rewrote my intentional exception" complaints.
  - Files: `scripts/detect.py:_handle_apply_fixes` reads `args.baseline`, skips matching findings.

- [ ] **P1 · M — `--mode diff` + `--baseline` composition.** When CI runs in diff mode, baseline still applies workspace-wide; should narrow to changed files. Source of false "regression" failures today.
  - Files: `scripts/detect.py:apply_baseline` accepts an optional `diff_files: set[Path]` parameter.

- [~] **P1 · L — `detect.py` modularization.** Started at 8,400+ LoC monolith; **four seams shipped** so far (`_mitre.py`, `_versions.py`, `_scoring.py`, `_hcl.py` — landed across R30.0.5, R30.0.6, R30.0.7). detect.py now ~7,990 LoC (8,441 → 7,991, −450 over four sub-rounds); the four extracted modules total ~740 LoC of pure-function helpers, all with re-export shims so callers don't migrate. The 629 passing tests are the safety net — refactor is incremental and proven. Remaining splits to do:
  - `engine/` — pattern dispatch (kinds), variable resolution, `find_blocks`
  - `output/` — JSON, SARIF, HTML, MITRE, compliance, text formatters
  - `attack_graph.py` — graph build, fix centrality, edge inference
  - `lsp.py` — JSON-RPC server
  - `plan.py` — plan-JSON dispatch
  - `scoring.py` — `_RISK_WEIGHTS`, `_compute_summary`
  - `catalog.py` — load + validate + `applies_when` filter
  - `cli.py` — argparse + `main`

  Bonus: each module gets independent test coverage that can be run in isolation.

- [ ] **P2 · M — Vendor an ATT&CK STIX bundle for richer per-rule docs.** R30.0.5 deferred this. Fetch `mitre/cti` `enterprise-attack.json` (~10 MB) once; cache at `scripts/_attack_v17.json`. Use it to populate platform / data-source / parent-technique blocks on per-rule docs pages — currently the docs pages only render the bare technique-ID link. Adds genuine reference content to the per-rule pages, compounds the C6 SEO investment. Defer until per-rule pages need richer content for SEO traction.

- [ ] **P2 · M — Procedure-example linking for adversarial narratives.** Depends on the STIX bundle above. The `_ATTACK_NARRATIVES` table in `detect.py` already cites real breaches (Capital One, SolarWinds, Tesla 2020) on 14+ rules; ATT&CK's procedure-examples tables list those same procedures. Wire the per-rule docs page to render both — curated narrative as the lead, ATT&CK's procedures as the appendix. Auto-populates "named adversary uses" for every mapped rule, not just the 14 hand-curated ones.

### a.2 Tier 2 — moderate leverage

- [ ] **P2 · M — `.tf-analyze-history.json` persistence.** Records `(rule_id, action, timestamp)` per workspace. Enables: deprioritise rules a user has consistently suppressed; surface "you've fixed this rule 12 times — consider `--apply-fixes` workspace-wide"; per-user/team trust score.
  - Files: `scripts/detect.py:_record_history`, `_load_history`. New `--no-history` opt-out.

- [ ] **P2 · M — `--watch` mode.** Persistent process pre-loaded with the catalogue (~150ms to load 215 YAMLs). Each `.tf` save → re-scan in <50ms. Effectively repurposes the existing LSP infrastructure as a CLI.
  - Files: `scripts/detect.py:_run_watch_mode`. Reuses `_run_lsp_server` minus JSON-RPC.

- [ ] **P2 · M — HCL-formatter pass on inserted `fix_hcl`.** When `--apply-fixes` inserts a snippet, indent and quote style come from the catalogue YAML, not the user's existing convention. Run a small in-Python `terraform fmt`-equivalent pass on the inserted hunk so patches read like the user wrote them.

- [ ] **P2 · M — Compliance + trend composition.** `--mode trend` + `--compliance` should produce a "your CIS coverage moved 67% → 73% over 30 days" trendline. Currently the two flags are mutually exclusive.

- [ ] **P2 · M — Catalog overlap audit.** Two rules with overlapping patterns can both fire on the same code (`ROB-AWS-RDS-001` and `ROB-AWS-RDS-002` both touch backup retention). With 217 rules, silent overlap is inflating finding counts. New script `scripts/audit_overlap.py` flags pattern-overlap candidates; not a CI gate but a maintenance tool.

- [ ] **P2 · M — Provider-version `applies_when` annotations.** Engine support since Round 1, only 2 rules use it. Sweep the catalogue for rules that *only* apply to specific provider majors (anything mentioning `metadata_options`, `ssl_mode`, `default_tags`, …) and add `min_provider`. Half-day data-entry pass.

- [ ] **P2 · L — More K8s + cloud-platform rules.**
  - `SEC-K8S-RBAC-002` — namespace-scoped binding to dangerous roles
  - `SEC-K8S-SECRET-001` — `kubernetes_secret` without encryption-at-rest
  - `SEC-AWS-CONFIG-001/002` — Config recorder + delivery channel absence
  - `SEC-AWS-SHIELD-001` — Shield protection absence for EIP/LB
  - `SEC-AZURE-DEFENDER-001/002` — Microsoft Defender for Cloud disabled
  - `SEC-GCP-BINARY-AUTH-001` — Binary Authorization not enforced on GKE

  Each: ~30 LoC catalogue YAML + 1 positive fixture + 1 clean fixture (auto-generatable for most).

- [ ] **P2 · S — Severity calibration round (20 more rules).** Spot-check current `default_urgency` against tfsec/checkov/Prowler equivalents; adjust where there's a clear delta. Document each move in `docs/severity-calibration.md`.

### a.3 Tier 3 — long-game

- [ ] **P3 · XL — Tree-sitter HCL parser replacement.** Currently regex with python-hcl2 fast-path. Tree-sitter gives proper AST + 10–50× speedup. Big lift; sequence after the modularization in Tier 1.

- [ ] **P3 · M — Engine SHA in summary output for drift detection.** Bundled-engine drift between extension and CI is a real risk. Emit `engine_sha` in `summary` (next to `scoring_version`), and have the extension's About dialog show it.

- [ ] **P3 · M — Custom rules in bundled-engine extension path.** `--config .tf-analyze.yaml` + `.tf-analyze-rules/` works against `detect.py` standalone. Document and wire the extension path so a workspace's custom rules pick up automatically without `tf-analyze.scriptPath` configuration.

---

## b) Test coverage

### b.1 Tier 1 — risk-driven gaps in code that ALREADY shipped

- [x] **P0 · S — Module Reuse Advisor isolated fixtures.** *(Already shipped: `fixtures/mod_reuse_aws_vpc/`, `fixtures/mod_reuse_azure_aks/`, `fixtures/mod_reuse_gcp_network/` plus matching `MOD-REUSE-*_clean` directories — wired into both `tests/test_fixtures.py` and `tests/test_clean_fixtures.py` parametrized suites. Cluster-fingerprinting code is now exercised by the canonical fixture pipeline.)* Three `MOD-REUSE-*` rules have zero `fixtures/` entries — they only fire inside `examples/module-reuse-demo/`. A regression in the cluster-fingerprinting code (Round-26 novel logic) would not be caught by `tests/test_fixtures.py`. Add `fixtures/MOD-REUSE-VPC-AWS-001/`, `fixtures/MOD-REUSE-NETWORK-GCP-001/`, `fixtures/MOD-REUSE-AKS-AZURE-001/` plus matching `_clean` fixtures.

- [x] **P0 · M — URI handler integration tests.** *(Round 27 — extracted URI dispatch into a pure function in `vscode-extension/src/uriHandler.ts` testable via `node --test` (the runner the rest of the extension uses); 24 cases in `vscode-extension/src/test/uriHandler.test.ts` cover validators, every verb, workspace scoping, and rejection of malformed/hostile inputs. Avoids the `@vscode/test-electron` dependency the plan suggested while delivering equivalent coverage of the dispatch logic.)* `extension.ts` registers `vscode://tfanalyze.tf-analyze/rule/...`. The regex validator probably has unit tests; no test simulates the URI and asserts the panel opens with the right content. Use `@vscode/test-electron`. File: `vscode-extension/src/test/uriHandler.test.ts` (NEW).

- [x] **P0 · S — JSON-LD validation against Schema.org spec.** *(Round 27 — `tests/test_rule_docs.py::TestSEOAndDeepLinks::test_jsonld_passes_schema_org_validator` plus a tighter cross-page sweep `test_jsonld_validates_across_every_rule_page`. Validates `@type`/`@context`, URL well-formedness, `mainEntityOfPage.@type`, controlled-vocab `proficiencyLevel`, and JSON-boolean `isAccessibleForFree`. Stdlib only — no `pyld`/`jsonschema` dependency.)* `TestSEOAndDeepLinks` checks required keys but not URL well-formedness, ISO-8601 dates, `mainEntityOfPage.@type`, etc. Search engines silently demote pages with malformed structured data. Use the `pyld` (or `jsonschema`) library against the published TechArticle schema. File: `tests/test_rule_docs.py::TestSEOAndDeepLinks::test_jsonld_passes_schema_org_validator` (NEW).

- [x] **P0 · S — Urgency-tier per-rule pinning.** *(Round 27 — `tests/test_output_formats.py::TestComputeSummary::test_module_reuse_urgency_pinned_to_info` walks every `MOD-REUSE-*.yaml` and asserts `default_urgency == INFO`. Same shape as the `_RISK_WEIGHTS` tripwire so any future urgency drift fails CI.)* Module Reuse findings are INFO (weight 0). A future change accidentally bumping them to MEDIUM would tank every score by 3pts/finding. Lock per-rule urgency in `tests/test_schema.py::test_module_reuse_urgency_pinned` similar to the `_RISK_WEIGHTS` tripwire.

- [ ] **P1 · M — LSP server JSON-RPC tests.** 200+ LoC of `_run_lsp_server` in `detect.py`, **zero tests**. The extension talks to it per-keystroke. A regression here surfaces as silent diagnostics-don't-appear.
  - File: `tests/test_lsp_server.py` (NEW). Spawn `python3 detect.py --lsp` as subprocess; send `initialize` → `textDocument/didOpen` with bad HCL → assert diagnostic returned → `textDocument/codeAction` → assert WorkspaceEdit. ~10 tests.

- [ ] **P1 · M — HCP Run Task server tests.** `integrations/run-task/server.py` has zero tests. HMAC-SHA512 verification, plan-JSON download, callback POST — three security-critical failure modes none tested.
  - File: `tests/test_run_task_server.py` (NEW). Use FastAPI's `TestClient`. ~6 tests.

- [ ] **P1 · M — `--mode plan` / `--plan-json` tests.** Alternative pattern-dispatch path (~200 LoC). Divergence from the static-mode path is silent today.
  - File: `tests/test_plan_mode.py` (NEW). Synthetic plan-JSON (manually crafted, no Terraform required). ~6 tests.

- [ ] **P1 · M — Catalog invariant tests.** Extend `tests/test_schema.py`:
  - Every `cis:` matches `\d+(\.\d+)+` (or the structured-form schema)
  - Every `mitre:` matches `T\d{4}(\.\d{3})?`
  - Every `fix_disruption` is in the enum
  - Every regex compiles on Python 3.11+ (would have caught the `^(?i)` Round 26 bug)
  - Every `applies_when.min_provider` constraint parses
  - No duplicate IDs across catalogue files

- [ ] **P1 · S — Determinism test.** Scan same input twice, assert byte-identical JSON output. Catches dict-ordering bugs that surface intermittently.
  - File: `tests/test_output_formats.py::test_scan_is_byte_deterministic` (NEW).

- [ ] **P1 · S — Determinism guard for `gen_rule_docs.py` under CI.** `--check` mode passes today but doesn't assert there's no timestamp/date drift. If the generator ever embeds a timestamp, CI starts flaking on every push. Add: `tests/test_rule_docs.py::test_generator_output_has_no_dynamic_dates`.

- [ ] **P1 · L — Property-based tests for HCL primitives.** `hypothesis` against `block_arg_value`, `_resolve_var_ref`, `_expand_dynamic_blocks`, `_hcl_object_to_json`. Each gets ~20 lines, robustness gain disproportionate. Catches malformed-HCL crashes the fixture suite never exercises.
  - File: `tests/test_hcl_primitives.py` (NEW).

### b.2 Tier 2 — broaden the safety net

- [ ] **P2 · S — Apply-fixes round-trip extended to `nested_path` `resource_missing_arg`.** Round-26 patcher couldn't handle nested-block insertion. After the engine fix lands (Tier 1 a.1), expand `ROUNDTRIP_CASES` in `tests/test_apply_fixes.py`.

- [ ] **P2 · M — LSP perf budget test.** Distinct from `test_perf.py`. Assert single-file LSP scan < 80ms on a representative 200-line `.tf` file. Without this, an O(n) regression that adds 50ms per rule check ships silently and degrades the IDE feel.
  - File: `tests/test_lsp_perf.py` (NEW).

- [ ] **P2 · M — Web demo (`demo/app.py`) tests.** Rate limit, scan-cap, repo-URL validation all untested.
  - File: `tests/test_demo_app.py` (NEW). FastAPI `TestClient`. ~8 tests.

- [ ] **P2 · L — VS Code extension `@vscode/test-electron` smoke.** Open `.tf` file, save, assert diagnostic appears, invoke Quick Fix, assert edit applied, run "Show Attack Graph", assert webview HTML contains node count > 0. Catches v0.1.8-class regressions (the blank-panel bug that survived three releases).
  - File: `vscode-extension/src/test/smoke.test.ts` (NEW). ~6 tests.

- [ ] **P2 · M — `vscode-extension/src/test/remediationPanel.test.ts`.** `remediationPanel.ts` (276 LoC, the most complex extension module) has no tests — and it's the single most destructive code path (rewrites user files). Critical for v1.0.

- [ ] **P2 · M — Screenshot/landmark regression on docs pages.** A future Cayman theme upgrade could quietly strip the JSON-LD script tag (HTML minifier eating `<script type="application/ld+json">`). A curl-and-grep guard per page that confirms specific landmark elements ("Open in VS Code" button, JSON-LD script, family backlinks) catches it. Could be `tests/test_docs_site_landmarks.py` that hits the rendered output (or a Pages preview build).

- [ ] **P3 · L — Mutation testing.** `mutmut` against `detect.py` pattern-matching functions. Quarterly run; long-running. Asserts whether fixtures actually exercise code paths or pass by accident. Defer until after the modularization in Tier 1.a.

---

## c) Virality — engineering items only

The publication / launch lever is **operator-only** (see Appendix). What
Claude Code can build in service of virality:

### c.1 Tier 1

- [x] **P0 · S — Status-bar score badge with grade colour.** *(Round 27 — `extension.ts:setFindings` reads `summary.score`/`summary.grade` and prefixes the bar text. `_gradeColor()` maps grade → `vscode.ThemeColor("charts.green/blue/yellow/orange/red")` so the bar visibly reds out at F. Colour resets on scan-start/error to avoid stale visual state.)* Currently the extension shows `🛡 tf-analyze: 7 (C:1 H:2 M:4)`. Add the score+grade prefix from the engine's summary block: `🛡 tf-analyze: 82 (B) · 7 findings`. Visible everywhere a user has the extension installed. The grade is the inherently shareable artefact — screenshots get posted.
  - Files: `vscode-extension/src/extension.ts:setFindings` reads `summary.score` / `summary.grade`.

- [x] **P0 · M — Live "security score" badge service.** *(Round 27 — `integrations/badge-service/` Fly.io app: `server.py` (FastAPI) + `Dockerfile` + `fly.toml` + `scripts/upload-score.sh`. SVG renderer keyed by grade colour; `/score/<owner>/<repo>.svg` and `/score/<owner>/<repo>/<branch:path>.svg` (handles `release/v1.0`-style branches); `/ingest` accepts the engine's JSON output authenticated via HMAC-SHA256 over the request body. 19 tests in `tests/test_badge_service.py` (auto-skipped if FastAPI not installed). Operator step: `flyctl deploy`.)* A small static-asset endpoint that returns an SVG badge per repo: `![tf-analyze](https://tf-analyze-badge.../score/<owner>/<repo>.svg)` rendering "62 (C)" with the grade colour. Embeddable in any README. Each rendered badge is an ad. Stretch: per-PR badge showing delta.
  - Files: new `integrations/badge-service/` (Fly.io app) — operator must deploy, but engineering deliverable is the code + Dockerfile.

- [ ] **P1 · M — Trend output as a graph image.** `--mode trend` currently emits text. Adding `--format svg` (or `--format png` via `python-svgwrite`) for the trend timeseries makes the output embeddable in PR summaries and team dashboards.
  - Files: `scripts/detect.py:_render_trend_svg` (NEW).

### c.2 Tier 2

- [ ] **P2 · M — PR comment Mermaid attack-graph snippet.** When the GitHub Action posts the summary comment, append a collapsible section with the attack-graph mermaid (existing `--format text --attack-graph` output already produces it). Every PR reviewer sees the graph.
  - Files: `action.yml` (the github-script step appends mermaid to summaryBody).

- [ ] **P2 · S — Hardened-repo demo.** `examples/well-formed/` — what a perfect (score 100, A) Terraform corpus looks like. Side-by-side with terragoat in `docs/launch/` lets readers see "this is what tf-analyze rewards". Currently we only show what it punishes.
  - Files: `examples/well-formed/` (5–10 .tf files), update `docs/launch/launch-checklist.md`.

- [ ] **P2 · M — `--format pr-summary` Markdown block.** A minimal one-block summary suitable for PR descriptions: score, top-3 findings, top fix, attack-graph node count. Distinct from the verbose JSON/text output.

---

## Appendix: Operator-only items

These cannot be done by Claude Code; they require Marketplace UI clicks,
authenticated tooling on the operator's machine, screen recording, or
social posting. Listed here so the picture stays complete.

### Publication

- [ ] Click "Publish to Marketplace" toggle on the v0.1.0 GitHub Release page (the *one-click* gate that has remained closed for four analyses)
- [x] `vsce publish` (VS Code Marketplace) — done; verified live
- [x] `ovsx publish` (Open VSX) — done; verified live
- [ ] `flyctl deploy` for `demo/`
- [ ] Register `tf-analyze.dev` (or chosen) domain
- [ ] `./scripts/setup-repo-metadata.sh ChrisAdkin8/tf-analyze` (description + topics via `gh`)

### Marketing / launch

- [ ] Record 30-second LSP-narrative GIF (typing `aws_iam_user`, save, narrative pop, Quick Fix)
- [ ] Record 30-second docs-site → IDE round-trip GIF (PR comment → docs page → "Open in VS Code" → rule explainer → fix)
- [ ] Embed both GIFs in `README.md` hero (replace the static banner)
- [ ] "Show HN" post per `docs/launch/hacker-news.md`
- [ ] r/Terraform launch post per `docs/launch/reddit-terraform.md`
- [ ] Open the pre-commit.com hooks-index PR per `docs/launch/pre-commit-hooks-pr.md`
- [ ] HashiCorp Discuss thread + LinkedIn announcement

### External verification

- [ ] Validate SARIF v2.1 output against the OASIS schema (`sarif-tools` CLI)
- [ ] Manual UX review of compliance HTML in real-world auditor workflow
- [ ] First external-user friction report

---

## How to use this plan

1. **Pick a Tier-1 item from `a)` or `b)`** — both pillars have parallel tracks; the items they hold are independent and can be worked on in parallel.
2. **Open a feature branch** named after the item (`feat/module-reuse-roi`, `test/lsp-jsonrpc`, etc.).
3. **Land it with the listed test file in the same PR** — every item in this plan ships with its test entry-point.
4. **Tick the box, push, mark done in `CHANGELOG.md`.** This file stays the rolling backlog; CHANGELOG records what landed.
5. **When a tier empties, sweep the next tier — or run a fresh deep analysis.** The five analyses to date have all converged on the same publication blocker; the engineering backlog has continued to refresh itself with each round.

---

*Generated 2026-05-09 from the five deep analyses in this session.
Update by re-running the analysis prompt after a sprint or two of work
— items will graduate, and new candidates will surface as the project
surface grows.*
