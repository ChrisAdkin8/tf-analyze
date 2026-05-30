# tf-analyze — Audit Backlog (deep analysis 2026-05-29)

Triaged backlog from a six-subsystem deep analysis (core engine, output/scoring/fixes,
network integrations, VS Code extension, build/CI/packaging, tests/fixtures/catalog).

**Legend**
- `[✓]` = root cause independently verified this session (ran/read the code).
- `[~]` = reported by subsystem audit; consistent with sampled code but not independently re-executed.
- Locations are `file:line` against the canonical `scripts/` (not the generated `vscode-extension/engine/` copy).

---

## DONE (this session)

### Policy-as-code DSL v1 (2026-05-30) — the audit's #1 capability gap

Author cross-resource / conditional / aggregate rules as catalogue data
(`kind: policy`) — no Python, no vendored Rego. `scripts/_policy.py` (safe
hand-rolled parser + evaluator + a regex/"hcl1" resource view with scalar/list/
bool coercion), `scripts/_handlers_policy.py` (corpus handler), load-time
expression validation in `_catalog`, 19 tests in `tests/test_policy_dsl.py`
(unit + end-to-end through `detect.py`). User guide `docs/policy-dsl.md`; design
`tasks/policy-dsl-draft.md` (de-risked by the §7 evaluator spike, which caught a
draft bug + a parser bug). **Remaining:** Scope-A hcl2 attr accessor (removes
repeated-block/coercion limits), graph predicates (phase 2), first shipped
catalogue policy rules (now trivial catalogue data). Suite: **1208 passed**.

---

### main() refactor — Option A increment 1 (2026-05-30)

Began shrinking the ~1500-line `main()` by extracting early-exit dispatch
bodies into module-level helpers, matching the existing
`_cmd_list_rules`/`_cmd_explain`/`_cmd_new_rule`/`_pr_review_mode` pattern.
This increment: `_cmd_init`, `_mode_fleet`, `_mode_trend` (verbatim moves, same
exit codes / stderr markers / side effects). Guarded by new characterization
tests `tests/test_main_mode_dispatch.py` (the dispatch path had **no** e2e
coverage before). Suite: **1211 passed**.

### main() refactor — Option A increment 2 (2026-05-30)

Continued in recommended order. Extracted: **`_mode_verify_fixed`** (early-exit
mode set now complete), **`_cmd_apply_fixes`** (returns a bool — True ⇒ main
exits after a real apply; dry-run falls through), **`_cmd_auto_stub`**, and the
**`_make_emitter(args) -> (emit, out_file)`** polish. All verbatim/behaviour-
preserving. New characterization tests: verify-fixed (error + json happy path),
auto-stub (`--propose-stub`), and a **`--output`** file guard (that path had no
coverage). `apply-fixes` was already guarded by `test_apply_fixes_composition`.
Suite: **1215 passed**. `main()` body ~1465 → ~1339 lines.

Deliberately did **not** collapse `(emit, out_file)` into one emitter object —
that churns all ~30 `_emit(...)` render-block call sites for marginal gain;
do it when the render block itself moves.

**Remaining (Tier 4 — the real size of `main()`, high blast radius):**
- **`_render_report(...)`** — the `args.format` dispatch (text/json/sarif/html/
  compliance/mitre/pr-summary). ~860 lines, but note it appears **duplicated**
  across the compare-delta branch and the normal branch — extracting unifies
  them. Consumes ~10 locals (findings, entries, suppressed, suppressed_by_
  baseline, attack_graph, centrality_scores, compliance_report, blast_radius_
  top, summary, delta, emit). **Well-guarded** by `tests/test_output_formats.py`
  — lower behaviour risk than the mode bodies, but a large diff.
- **`_run_scan(...) -> findings`** — diff/plan file-set resolution + detect loop.
  Harder: the post-detect pipeline (enrich → baseline → threat-intel → INFO-
  filter) reassigns `findings` ~5× inline before render, so the boundary is
  fuzzy. Best paired with the `_render_report` extraction as one dedicated PR.
- Smaller safe slices available first if desired: `_apply_threat_intel(...)`
  (guarded by `test_threat_intel`), `_write_compliance_pdf(...)`.
- `--mode drift` rides with `_run_scan` (re-evaluates within the scan path,
  not a clean early-exit).

---

### P1/P2/P3 backlog sweep (2026-05-30)

Cleared the bulk of the remaining P1/P2/P3 list. Suite after the sweep:
**Python 1189 passed / 2 skipped, extension 68 passed**, zero regressions.

**P1** — catalog `kind` strict-load test (catches a typo'd/undispatched rule that would
silently never fire); MOD-STALE-001 wired to its `mod_stale_version` fixture (fixes the
malformed `fixtures: []`, closes the orphan, and proves the rule fires).
**P2 (engine)** — delta/baseline now uses multiset counts (resolved findings no longer hidden);
Markdown summary cells escape `|`/newlines (`_md_cell`); `_diff` two-dot fallback warns instead
of silently scanning nothing; risk score floors (no parity-dependent grade flips); MITRE/CWE/
D3FEND + SARIF-relationship ratchets tightened to ~5pts of current.
**P2 (VS Code)** — `tf-analyze.pythonPath` + platform-aware interpreter (Windows fix); Quick Fix
guards a stale/shrunk buffer; attack-graph + rule-explainer panels get the 120s timeout.
**P2 (integrations)** — `tf-analyze-security` pre-commit hook fixed (`--section` → `--focus`).
**P3** — `strip_hcl_context` is string-aware; `block_has_nested_path`/`_expand_dynamic_blocks`/
`_extract_provider_constraints` migrated onto `brace_walk`; findings de-duplication; PR-diff
`\ No newline` marker no longer shifts line→position; SARIF crash/`ruleIndex` (also P1-listed);
`install.sh --copy` strips build artifacts; Terraform-provider Go CI job (`go build/vet/test`);
`.github/dependabot.yml` for GitHub Actions. Tests in `tests/test_p2_p3_fixes.py` +
`vscode-extension/src/test/scriptResolver.test.ts`.

**Deferred (with rationale — NOT silently dropped):**
- `block_has_arg` depth-0 restriction — *reverted*: several rules legitimately match an arg
  nested in a sub-block (Cloud SQL `settings{}`, K8s ingress), so a blanket restriction
  false-positived their clean fixtures. Correct fix = per-rule migration to
  `block_has_nested_path` after intent review.
- Mutable-in-place enrichers — latent (the CLI emits one `--format` per run, so cross-format
  mutation doesn't occur in practice); fixing needs per-format deep-copy in `main()`'s dispatch.
- The two never-fired greps (`SEC-LOG-CROSS-ACCOUNT-001`, `STK-K8S-IMAGE-SIGNED-001`) —
  *intentionally* deferred by their own catalog comments ("until kubernetes_manifest walker").
- The ~79 remaining clean fixtures (negative coverage) — ongoing fixture authoring, not a discrete bug.
- Full commit-SHA pinning of all ~28 Actions — Dependabot added now; hand-pinning risks
  mis-resolving a SHA and breaking the (now-required) CI gate.
- `appendIgnoreRule` async + YAML-lib rewrite, and a goreleaser release pipeline for the provider.

---

- [x] **HCL parser family — silent false negatives.** Root cause: load-bearing primitives
  re-implemented naive, string/comment-blind brace counters instead of using the shared
  walker. Fixed by routing `find_blocks`, `find_simple_blocks`, `block_has_nested_path`
  through `brace_walk`; extending `block_arg_value` to capture multi-line `[]`/`{}`/`()`
  values; fixing `_extract_terraform_version` to brace-walk the `terraform{}` body; and
  making `brace_walk` **comment-aware + double-quote-only** (HCL has no single-quoted
  strings — the old single-quote tracking broke on apostrophes in comments).
  Files: `scripts/_hcl.py`, `scripts/_versions.py`. Tests added in
  `tests/test_detection_core.py` + `tests/test_hcl_primitives.py`.
  Verified end-to-end: idiomatic multi-line IAM policy now fires `SEC-AWS-IAM-POLICY-001/003/005`.

- [x] **P0 #1 — run-task SSRF + fail-open auth.** `integrations/run-task/server.py`. Now fails
  **closed** when `TFA_RUN_TASK_HMAC_KEY` is unset (opt-in `TFA_RUN_TASK_ALLOW_INSECURE=1` for
  local dev); `plan_json_api_url`/`task_result_callback_url` validated against an HCP/TFE host
  allow-list (`TFA_RUN_TASK_ALLOWED_HOSTS` to add TFE hosts) with `is_global` public-IP rejection
  before any request; `allow_redirects=False` on both calls; 50 MB streamed download cap
  (gzip-bomb guard). 7 tests in `tests/test_run_task_hardening.py` (fail-closed, allow-list,
  metadata/private-IP rejection, suffix-confusion).

- [x] **P0 #2 — apply-fixes file corruption.** `scripts/_apply_fixes.py`. Added an idempotency
  guard (`_block_has_top_level_arg` — skip insert if the arg is already present at depth-1), a
  depth-aware attribute replace (prefer the resource's own attribute, never clobber a same-named
  nested key; falls back to first-match so nested-target rules don't regress), and a
  misattribution guard (`_line_opens_finding_resource` — don't patch a block the forward scan
  overshot into). 3 regression tests in `tests/test_apply_fixes.py`.

- [x] **P0 #3 — pip packaging dead on arrival.** `pyproject.toml` + `scripts/detect.py` +
  `catalog/__init__.py`. Corrected `build-backend` → `setuptools.build_meta`; install the flat
  engine modules via `package-dir`/`py-modules`; ship the catalogue as the `tf_analyze_catalog`
  data package; `_default_catalog_dir()` resolves env → source/bundle sibling → installed package
  (so dev/Docker/VSIX are unchanged). Version bumped `0.1.0` → `0.2.6`. **Verified in a throwaway
  venv:** `pip install .` → `tf-analyze --list-rules` shows 351 rules and a scan from outside the
  repo detects IAM wildcards.

> **Full suite after all P0s: 1172 passed, 2 skipped (+10 new tests), zero regressions.**

- [x] **V4 — `--cache` security-control bypass.** `scripts/detect.py` now folds the full scanned
  set (`{**all_text, **extra_text}`) into `_corpus_hash`, so a change to a workflow YAML / tfvars
  invalidates the cache instead of a warm cache silently skipping it. Regression tests in
  `tests/test_cache.py` (invalidate-on-extra-file-change + stable-hit-when-unchanged).

- [x] **V1 — Public-scanner DoS.** `demo/app.py`. Extracted `_enforce_clone_caps` and applied it
  to `/scan/repo` (+ added `--filter=blob:limit=1m`) and `_clone_and_trend`; added `_run_capture`
  (Popen+kill) so engine/git subprocesses are reaped on timeout; `_rate_check` now evicts stale
  buckets past a table cap. 5 tests in `tests/test_public_scanner.py::TestCloneCapsAndRateLimit`.

- [x] **V2 — Stored XSS in HTML reports.** Escaped the three raw sinks via `html.escape`/`_h`
  (`_blast_radius.py:202`, `_output.py` control + framework). XSS regression tests in
  `tests/test_blast_radius.py` + `tests/test_compliance_owasp_iac.py`.

> **Full suite after V4/V1/V2: 1181 passed, 2 skipped (+9 tests), zero regressions.**

---

## P0 — Critical

All three original P0s are **fixed and verified this session** — see DONE above.

---

## 🔴 Next tranche — critical vulnerabilities (the security tier after P0)

**ALL FOUR (V1, V2, V3, V4) are FIXED and verified this session** — see DONE above for V1/V2/V4.

- [x] **V3 — VS Code webview XSS.** `vscode-extension/src/`. Re-verification corrected the audit's
  premise (the engine report *does* contain inline scripts, so "sandbox with no `allow-scripts`"
  would break it). Fix: `sandbox="allow-scripts"` (opaque origin → injected XSS can't reach the
  parent webview / VS Code API) on both report iframes (`htmlReport.ts`, `compliancePanel.ts`),
  a CSP `<meta>` injected into the report doc (`injectReportCsp` in `iframeBridge.ts`:
  `default-src 'none'; connect-src 'none'` blocks exfiltration — matches the attack-graph panel),
  and `_escape` on the unescaped workspace path in `attackGraph.ts:70`. 4 tests in
  `src/test/iframeBridge.test.ts`; `tsc` clean; **66 extension tests pass**.

- [x] **V4 — `--cache` security-control bypass.** (See full entry in DONE above.) `corpus_hash` now
  folds the full scanned set so a workflow-YAML/tfvars change invalidates the cache.

> The whole 🔴 tier is closed. V1+V2 cleared the **deploy-`tfanalyze.com`** security gate — the
> public scanner is now safe to ship. V3 ships with
> the extension.

---

## P1 — High

- [ ] `[✓]` **Stale-cache silent misses.** `scripts/_cache.py:23` + `scripts/detect.py:~2505`.
  `corpus_hash` covers `.tf` files + catalogue only; the non-`.tf` scan (`extra_text`:
  workflow YAML, `.tfvars`) runs only on cache-*miss*. A secret added to
  `.github/workflows/deploy.yml` with a warm `--cache` is silently missed; tfvars-driven
  `var_defaults` are also outside the key.
  **Fix:** fold every input the scan consumes (extra files + resolved var defaults) into the hash.

- [ ] `[~]` **CI is good but not enforced.** `main` is unprotected + `allow_auto_merge` on, so
  auto-merge can ship a red PR. ci.yml already runs the full matrix + drift gates + bundle smoke.
  **Fix:** require the ci.yml job names as status checks on `main`.

- [ ] `[~]` **Stored XSS in offline HTML reports.** `scripts/_blast_radius.py:202` (resource
  cell), `scripts/_output.py:1616,1621` (compliance control/framework), plus the same surface in
  `demo/app.py:392-433` and the VS Code panels. Crafted resource/control names execute JS when a
  report is opened/shared.
  **Fix:** route every interpolated field through the existing `_h`/`html.escape` helper — no exceptions.

- [ ] `[~]` **SARIF emit is brittle.** `scripts/_output.py:464-485`. Direct `f["resource"]/["file"]/
  ["line"]` subscripts → one finding missing a key `KeyError`s the *entire* SARIF output (no
  safety-net wrapper, unlike pr-summary). `ruleIndex` defaults to `0` → unknown-rule findings
  mis-map to `rules[0]` in GitHub Code Scanning.
  **Fix:** `.get` with defaults; skip/synthesize unknown rules instead of defaulting to 0.

- [ ] `[~]` **Test design hides false positives.** `tests/test_fixtures.py` + `detect.py:2308`.
  Positive fixtures run with `--only-fixture`, which pre-filters the catalog to just the declaring
  rule → the "no unexpected rule fired" assertion is vacuous for 339/346 fixtures. And **93 rules
  (incl. 14 CRITICAL: IAM-JSON family, secrets, state, GCP network) have no clean fixture**, so
  they're never proven not to false-positive.
  **Fix:** run positive fixtures against the *full* catalog asserting `expected ⊆ actual`; add
  clean fixtures for the 14 CRITICAL rules first.

---

## P2 — Medium

### Engine / output
- [ ] `[~]` **Delta/baseline under-reports resolved findings.** `_baseline.py:199`. Match key
  collapses multiple same-rule findings on one resource into a `set`; fixing one of two reads as
  "unchanged". Use multiset (`Counter`) semantics.
- [ ] `[~]` **Markdown tables break on `|`/newline** in titles/resources. `_output.py:1450`,
  `_modes.py:124`. Add a `_md_cell()` escaper (relevant since `--catalog` accepts user content).
- [ ] `[~]` **`trend_*` git calls lack timeouts** and swallow per-SHA errors. `_modes.py:150-192`.
  Route through a timeout-bearing helper like `_diff._run_git`.
- [ ] `[~]` **`_diff.py` two-dot fallback** doesn't re-check `returncode` (`_diff.py:124-152`) → a
  bad `--diff-base` silently yields "0 changed files" / scan-nothing. Emit a WARN + decide explicitly.
- [ ] `[~]` **Scoring rounding direction** (`_scoring.py:205`) uses banker's rounding on `X.5`
  half-weights — a single suppression can flip the grade up or down non-obviously. Pick + document
  `floor` (penalty model) and update the `formula` string.

### Catalog / tests
- [ ] `[~]` **Catalog `kind` not validated** (`_catalog.py:235`) despite comments claiming it is —
  a typo'd `kind` silently never fires. **Add a CI test** running `load_catalog(strict=True)` and
  asserting `kind ∈ registered handlers`. (Also closes the `except Exception: continue` parse-mask
  in `helpers.py:62` and `test_rule_docs.py`.)
- [ ] `[~]` **Coverage ratchets have 12-28 pts of slack** (`test_mitre_cwe_d3fend.py`,
  `test_sarif_taxonomies_and_refactor.py`): e.g. MITRE gate `>=60%` vs 80% actual. Tighten to
  within ~5 pts of reality, or assert "no security rule lacks a MITRE tag".
- [ ] `[~]` **2 rules never proven to fire** (`SEC-LOG-CROSS-ACCOUNT-001`,
  `STK-K8S-IMAGE-SIGNED-001`) — both `grep`-kind, no dirty fixture. Add one each.
- [ ] `[~]` **Orphan/dead fixtures + malformed `fixtures: []`.** Rename `false_positive_*` dirs to
  `<RULE-ID>_clean`; wire `mod_stale_version` into `MOD-STALE-001.fixtures` (currently `[]`, which
  the in-repo `load_yaml` parses as the literal string `'[]'` — teach it inline-list syntax or
  forbid it).

### Demo scanner (public, live on Fly.io)
- [ ] `[~]` **`/scan/repo` DoS** — clones with no blob/size/file cap (other routes have them).
  `demo/app.py:681-697`. Route through the guarded `_clone_and_scan` path or remove the legacy route.
- [ ] `[~]` **`/trend` DoS** — deep all-branch clone + 300s engine timeout, no `.tf` caps.
  `demo/app.py:757-778`. Apply caps; consider async/queued.
- [ ] `[~]` **`subprocess.run(timeout=)` doesn't reap the child** on timeout (`demo/app.py:189-206`
  et al.) → orphaned git/python accumulate. Use the `Popen`+`kill()` pattern already in
  `run-task/server.py:113-120`.
- [ ] `[~]` **Per-IP rate-limit dict never evicts** (`demo/app.py:66,171-177`) — slow memory growth;
  also per-process + proxy-IP confusion. Use a TTL cache; decide on `X-Forwarded-For`.

### VS Code extension
- [ ] `[~]` **`<iframe srcdoc>` reports have no `sandbox`/CSP** (`htmlReport.ts:177`,
  `compliancePanel.ts:149`) — escaping is the only defense. Add `sandbox` (no `allow-scripts`) + CSP.
- [ ] `[~]` **Unescaped workspace path XSS** in the attack-graph "not found" panel
  (`attackGraph.ts:70`, rendered raw at `:176`). Wrap with `this._escape` like the other 6 panels.
- [ ] `[~]` **`python3` hardcoded at all 5 spawn sites** (`extension.ts:655`, `engineRunner.ts:81`,
  `attackGraph.ts:80`, `ruleExplainer.ts:70`, `lspClient.ts:42/49`) → broken on Windows. Add
  `tf-analyze.pythonPath` + platform-aware probe; clearer ENOENT message.
- [ ] `[~]` **Stale Quick Fix** applies against a possibly-edited buffer with no `document.version`
  guard (`extension.ts:964-984`); `lineAt` can throw if the file shrank. Capture + check version; clamp.
- [ ] `[~]` **Attack-graph + rule-explainer spawns miss the shared timeout** (`attackGraph.ts:79`,
  `ruleExplainer.ts:70`) — route through `runEngine`.
- [ ] `[~]` **`appendIgnoreRule` sync I/O + naive YAML hand-edit** (`extension.ts:526-575`) can dup
  the `ignore_rules:` key on inline-array files. Use async `workspace.fs` + a YAML lib.

### Integrations
- [ ] `[✓]` **`tf-analyze-security` pre-commit hook is shipped broken.** `.pre-commit-hooks.yaml:22`
  passes `--section security`, but the engine flag is `--focus` (no `--section` exists) — the hook
  exits 2 with an argparse error for anyone who enables it. **Fix:** `--section` → `--focus`.

---

## P3 — Remaining parser-family members + lower-severity smells

- [ ] `[✓]` **`_extract_provider_constraints` shares the same inline, string/comment-blind brace
  counter** (`_versions.py:143-154`) just fixed elsewhere. Refactor onto `brace_walk` for consistency.
- [ ] `[~]` **`_expand_dynamic_blocks` naive loops** (`_hcl.py:523-551`) and the `[^}]*` captures in
  `ignore_changes_overuse` (`_handlers_robustness.py:259`), `templatefile_sensitive_leak`
  (`_handlers_security.py:439`), `provider_alias_module_mismatch` (`_handlers_infra.py:157`) — same
  truncate-at-first-nested-`}` class. Route through `brace_walk`.
- [ ] `[~]` **`strip_hcl_context` not string-aware** (`_hcl.py:174-208`) — blanks `#`/`//` inside
  string literals and misses a comment right after a closing quote. Replace the regex with a
  single-pass tokenizer (length-preserving) reusing the `brace_walk` state machine.
- [ ] `[~]` **No findings de-duplication** between `findings.extend(...)` and output — full-file
  grep scope can emit duplicates. Add a `(id, file, line, resource)` dedupe step.
- [ ] `[~]` **`block_has_arg`/`block_has_nested_path` match nested args as top-level** (`_hcl.py:376`)
  — `resource_missing_arg` can be falsely satisfied by a nested same-named arg. Restrict to depth-0.
- [ ] `[~]` **PR-review diff parser miscounts after `\ No newline at end of file`** (`detect.py:1485`)
  → comment posted on wrong line. Skip lines starting with `\`.
- [ ] `[~]` **Mutable-in-place enrichers** (`_output.py`, `_threat_intel.py`, `_baseline.py`) make
  multi-format output order-dependent. Deep-copy per format or return new dicts.
- [ ] `[~]` **GitHub Actions unpinned** (28 floating major tags incl. third-party
  `softprops/action-gh-release@v2` with `contents: write`); Dockerfile base by tag not digest.
  Pin to SHAs + Dependabot; pin base by digest.
- [ ] `[~]` **`terraform-provider/` has no CI or goreleaser** — can't reach the Terraform Registry
  and isn't built/tested. Add a Go CI job + goreleaser if Registry distribution is intended.
- [ ] `[~]` **install.sh `--copy` uses `cp -R`** (drags gitignored artifacts) and curl|bash has no
  checksum/signature path. `install.sh:86-88`.

---

## Feature gaps & enhancements

From a dedicated three-angle sweep — **capability/competitive** (vs Checkov / Trivy / KICS / Snyk /
Terrascan), **distribution/adoption**, and **UX/integrations**. Effort `S` = hours, `M` = days,
`L` = week+. **Fit** flags whether an item reinforces tf-analyze's stdlib-only, Terraform-first,
single-binary positioning or dilutes it.

### A. Capability & competitive

The one gap that gates org-wide adoption: **every** serious competitor lets users express
cross-resource / conditional guardrails; tf-analyze's custom rules are pattern-only (regex /
arg-presence). tf-analyze already builds a resource graph internally (attack-path BFS,
`_cross_resource.py`) — it just isn't exposed to user policy.

Build (good fit, ordered by value):
- [ ] **Native policy-as-code predicate layer** — expose the parsed resource model + graph through a
  declarative YAML/JSON predicate DSL (cross-resource, conditionals, counts). **M.** Fit: strong on
  need — but do **NOT** vendor OPA/Rego (Go/WASM dep breaks stdlib-only). A native DSL closes ~80%
  of the gap and keeps the single-binary identity; tradeoff is no Rego-library reuse for adopters.
- [ ] **Entropy / high-entropy-string secret detection** (Shannon entropy over string literals) to
  complement the regex secret rules. **S–M, strong fit** — pure stdlib, slots into the finding
  pipeline. Best capability quick-win. (Competitors: Trivy, Checkov.)
- [ ] **Deep external-module supply-chain scan** — `MOD-SUPPLY-*`/`SEC-SUPPLY-*` today check pinning/
  mutable-ref/version *metadata* only; fetch the referenced registry/git module and recurse the
  scanner over its source. **M, good fit** — reuses the engine; network fetch opt-in (like KEV/EPSS).
- [ ] **Terragrunt support** — `_hcl.py` brace-walker can parse the HCL, but `terragrunt.hcl`
  `include`/`generate`/`dependency` resolution is unhandled and `.hcl` is silently skipped. **M–L,
  good fit.** Scope a thin v1: resolve module `source` + scan the rendered output. (Also a UX item.)
- [ ] **Raw Kubernetes YAML** — the single highest-frequency adjacent format; many K8s rules already
  exist on the Terraform `kubernetes_*` path and could be retargeted. **M, partial fit** — pick ONLY
  this one adjacent format; chasing breadth dilutes "best Terraform tool."
- [ ] **JetBrains plugin** — wraps the **existing** `_lsp.py` (JetBrains supports LSP plugins), so the
  hard part is done. **M, good fit** — pure reach (large IntelliJ/GoLand infra-engineer base).

Integrate, don't build (deliberate non-goals — recorded so they're decided, not forgotten):
- [ ] **Container image CVE + SBOM** — Trivy's moat; owning a vuln DB + image extraction abandons the
  stdlib/offline identity. **Instead:** emit the list of image refs found in IaC so users pipe them
  to Trivy/Grype.
- [ ] **Multi-IaC breadth** (CloudFormation / ARM / Bicep / CDK / Pulumi) — a Terraform-first tool
  loses on its home turf here. Decline; raw-K8s-YAML (above) is the one exception.
- [ ] **Persistent SaaS dashboard / org fleet history** — inherently a hosted service; keep the CLI
  emitting JSON/SARIF/OSCAL and let the public surface own persistence. Aligns with the memory thesis.
- [ ] **License / dependency (SCA) scanning** — tied to the same DB-ownership burden; off-core.

### B. Distribution & adoption

**Key finding: the public surface is BUILT but NOT SHIPPED — the launch checklist
(`docs/launch/launch-checklist.md`) is ~100% unchecked.** So the highest-leverage moves are *flip
the switch on finished work*, not new engineering. (Reconciles with the memory thesis "build the
public surface" — sharpened to "ship the surface that already exists.")

Ship what exists (highest leverage):
- [ ] **Deploy the public scanner to `tfanalyze.com`** — code-complete in `demo/app.py` + `demo/fly.toml`;
  README badge (`README.md:15`) and the comparison table already advertise it. **THE critical path** —
  every growth-loop item below amplifies this surface. Deploy, not build. (Harden SSRF first — see P0.)
- [ ] **Flip three marketplace switches** — GitHub Action publish (`action.yml` has `branding:`),
  `vsce publish` + Open VSX for the extension (`publisher: tfanalyze`). Operator clicks; unlocks
  organic discovery on three top dev-tool storefronts. README badges link to listings that 404 today.
- [ ] **Fix + publish the PyPI package** (cross-ref **P0** packaging) — `pipx install tf-analyze` is the
  universal Python-tool install reflex and the prerequisite for Homebrew / asdf-mise / Trivy-plugin.
- [ ] **Submit to pre-commit.com hooks index** — PR text pre-written (`docs/launch/pre-commit-hooks-pr.md`);
  developers discover the tool in the same flow they add `terraform fmt`/`tflint`. (Fix the `--section`
  hook bug in P2 first.)

New packaging substrate (unblocks 5 channels):
- [ ] **Single-file binary** (`shiv` first; PyInstaller only if "no Python at all" demand) attached to
  GitHub Releases. **M.** Hard-gates Homebrew, asdf/mise, winget, and the Trivy plugin.
- [ ] **Homebrew tap / asdf-mise plugin / winget manifest** — thin manifests pointing at the release
  binary. **S each, gated on the binary.**
- [ ] **Trivy plugin** (`trivy plugin install tf-analyze`) — memory calls this "the highest single-step
  distribution multiplier"; gated on the binary.

Growth loop & reach:
- [ ] **Render an OG image + `summary_large_image`** on scanner/trend permalinks — today previews are
  text-only (`demo/app.py` has `og:title`/`description`, `twitter:card=summary`, **no `og:image`**).
  The score-badge SVG renderer (`demo/_badge.py`) already exists; a bold "Score 42 (F) · 12 CRITICAL"
  card multiplies share click-through. **S–M.**
- [ ] **"Scan another repo" + "copy this badge" CTAs** on the permalink (`_render_public_report`) —
  closes the referral loop (visitor scans → embeds badge → backlink → their readers click through).
- [ ] **Slack / Teams / Discord output** — a `--format slack`/`teams` (Block Kit / Adaptive Card JSON)
  the Action/CI POSTs to a webhook; reuses `_output.py`. Recurring passive exposure inside teams.
- [ ] **awesome-terraform / awesome-iac-security listings + new-rule RSS** — durable SEO backlinks;
  the 353 rule-doc pages already exist on Pages to feed an RSS stream. **S.**
- [ ] **GitHub App** for zero-config org-wide PR scanning (Checks-API annotations vs the per-repo
  workflow tax of the Action). **L — highest ceiling, defer until items above prove demand.**

> Note: `integrations/badge-service/` is **DEPRECATED** (its own README says so) — badge rendering
> was folded into the scanner's `/badge/` route in `demo/app.py`. Don't deploy it separately; the
> live badge ships with the scanner (item above). Supersedes the "badge service awaits flyctl deploy"
> note in the `project_round27_summary` memory.

### C. UX & integrations (DevEx)

Quick-win batch (all `S`, in `detect.py`/`_output.py`/docs — ship together):
- [ ] **Inline suppression with reason** — `# tf-analyze:ignore RULE-ID -- reason`. The inline-ignore
  regex (`detect.py:181`) + `_baseline.py:96` hardcode the reason to `"inline comment"`; thread a
  captured reason through to `suppression_reason`/SARIF for audit trails. (Competitive parity item too.)
- [ ] **`--version` flag** (+ a single `__version__` source of truth shared with Docker tags / bundled engine).
- [ ] **`--list-rules --format json`** — `load_catalog()` already returns structured dicts; branch + `json.dumps`.
- [ ] **Consolidated exit-code docs + `--quiet`** — semantics exist (`sys.exit(2)`, `--fail-on`) but are
  scattered; add a docs table and a flag to mute the `# …` stderr chatter.
- [ ] **CSV / flat tabular export** for GRC teams who live in spreadsheets (id, urgency, file, line, cis…).

CI-platform batch (first-class beyond GitHub Actions, via formats they already ingest):
- [ ] **GitLab CI component/template** (Docker image + SARIF already exist — thin wrapper) **+ GitLab
  SAST report JSON** (near-isomorphic to the SARIF emitter) for the native MR security widget.
- [ ] **JUnit XML output** — one format unblocks Jenkins / GitLab / Azure DevOps / CircleCI test tabs at once. **S–M.**
- [ ] **Azure DevOps pipeline template** (YAML wrapper first; defer the Marketplace task). **M.**

Config / enterprise stickiness:
- [ ] **Per-rule severity override + risk-score weighting** in `.tf-analyze.yaml` (currently only binary
  `ignore_rules`) — let orgs downgrade a noisy rule rather than silence it; apply before `_scoring.py`.
- [ ] **Shell completion** (bash/zsh/fish) — matters once there's a real PATH entrypoint (see PyPI fix);
  ~55 flags now, completion aids discoverability.

Foundational:
- [ ] **`pip`-installable console entrypoint** (`[project.scripts]`) + a documented stable REST `/scan`
  endpoint extracted from `demo/app.py` — prerequisite for shell completion and a normal install story.
  (Folds into the P0 packaging fix.)
