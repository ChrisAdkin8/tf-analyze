# tf-analyze repo audit — round 3 (post-R30.9 + ext v0.1.46)

**Date:** 2026-05-11 (after R30.9 / ext v0.1.46 shipped, closing 20 of 24 follow-up findings)
**Method:** Four parallel `Explore` subagents on distinct surfaces; ~38 raw findings synthesised + verified here. Subagent claims I could not reproduce on re-read are demoted or rejected.

**Surfaces audited:**
- Just-shipped R30.8 + R30.9 changes (regression-of-fix pass)
- `_output.py` (1.7k LoC, only sampled before) + the unaudited 80% of `detect.py` (`detect_in_file`, `detect_corpus`, `_extract_var_defaults_by_dir`)
- Test suite + maintenance scripts + bundle infrastructure
- Integrations (MCP, run-task, badge service, public scanner, GitHub Action, Terraform provider) + docs site

**Explicitly out of scope:** Everything closed by the round-1 audit (R30.8) and round-2 audit (R30.9). The 4 deferred items (god functions, `_output.py` CSS dedup, multi-root scan plumbing, `_catalog.py` quoted-key limitation) are tracked but not re-flagged unless this pass found *new* evidence.

---

## Critical bugs (real correctness risk — fix first)

| # | File:line | Risk | What breaks | Confidence |
|---|---|---|---|---|
| 1 | `scripts/detect.py:487-488` | **R30.9 `hcl_context` fix has a coordinate-space mismatch on block attribution** | The fix at lines 477-481 reports the correct line number against the original text — but the immediately-following loop at 487-488 still uses `m.start()` (a stripped-text offset) against `blk["start_pos"]` (an original-text offset). Findings emitted under `hcl_context: true` end up with the right line but the **wrong resource attribution**, or no attribution at all. | **HIGH** — verified by reading the surrounding code: the two offsets live in different coordinate spaces and are compared as if they didn't. |
| 2 | `scripts/detect.py:479` | **R30.9 `hcl_context` fix uses `text.find(matched)` — first-occurrence collision** | `text.find(matched)` returns the FIRST occurrence in the original text. If the matched bytes appear in an earlier comment (which the strip pass removed, but `find` sees it in the original) the reported line is wrong in a *different* way than the prior bug. The fallback "rare collision" comment minimises this — but rule patterns matching common attribute names (e.g., `encrypted = false`) collide reliably. | **HIGH** — direct read; the docstring acknowledges the risk but accepts it. The right fix is to track a stripped→original offset map. |
| 3 | `tests/helpers.py:26-29` | **`run_detect` swallows `JSONDecodeError` and returns `[]`** | The test driver catches malformed engine output and returns an empty list. A test like `assert run_detect(target) == []` passes whether the engine succeeded with no findings OR crashed with a Python traceback. The same shape the round-2 audit closed for `check_terragoat_snapshot.py` and `test_rule_docs.py` lives here unchecked. | **HIGH** — direct read; trivially reproducible by pointing `run_detect` at a path that triggers an engine crash. |
| 4 | `scripts/self_test.py:64-78` | **Self-test exit code does not reflect engine crashes** | Reads `result.stdout` and calls `json.loads()` without first asserting `result.stdout.strip() != ""`. An engine crash (exit 1, empty stdout, traceback in stderr) raises `JSONDecodeError` deep in the helper with no diagnostic context — and is caught by an outer `try` in many cases, silently treating "I crashed" as "no findings". | **MEDIUM** — needs verification by running against a deliberately-broken engine, but the code path is unambiguous. |
| 5 | `integrations/github-action.yml:137-146` | **JSON parse step has no exception handler** | The Python snippet that reads `tf-analyze-findings.json` calls `json.load(...)` with no `try/except`. If detect.py crashed between the `2>tf-analyze-stderr.txt \|\| true` redirect (line 104) and the JSON write, the step fails with a Python traceback visible only in the Action log. The PR-comment step (line 224) then runs with an undefined `findings` list and emits malformed output. | **MEDIUM** — reproducible by introducing any engine crash; CI shows the traceback. |
| 6 | `integrations/terraform-provider/internal/provider/scan_data_source.go:341-345` | **Compliance failure downgraded to `AddWarning`** | If the compliance step fails (framework typo, engine exit 2), the provider sets `data.ComplianceReport = ""` and emits an `AddWarning`. Downstream HCL using `precondition` on the report text sees an empty string. A user gating `terraform apply` on "compliance report contains X" silently passes the gate when the compliance run itself died. | **MEDIUM** — verified by reading the provider; the warning vs. error split is a deliberate but wrong choice. |

---

## High-severity smells

| # | File:line | Smell | Why it matters |
|---|---|---|---|
| 7 | `scripts/_lsp.py:175` (R30.9 fix) | **`inspect.signature` arity assertion with `*args` accepts up to 10,000 args** | The assertion at module entry rejects scanner-arity drift unless the callable has `*args`, in which case the upper bound becomes `10_000` (effectively any). The interface IS fixed — the wrapper should never be `*args`-bearing. Use an `is False` clause that explicitly rejects varargs instead. The error message also reads "accepts 0..10000" which is confusing. |
| 8 | `tests/test_hcl_primitives.py:118` | **Property tests with conditional assertions** | `@given(...) ... if result is not None: assert result == value` — the assertion is guarded away when `result` is `None`. A regression that causes the function to always return `None` would pass these tests. Same shape: `test_quoted_value_strips_quotes` at line 117. Better to assert the contract unconditionally (define when the function should return `None` and assert *that* too). |
| 9 | `scripts/detect.py:538-1003` (12 detector branches) | **Brace-walking depth logic duplicated across 12 pattern kinds** | The prior audit flagged this as a god-function (#9, deferred). Confirmed at finer grain: brace-balance extraction is copy-pasted in `iam_policy_analysis` (636-651), `helm_set_value` (730-743), `security_group_rule_analysis` (885-906), `hcl_attr` (987-1003), and others. A consistent fix for CRLF, escaped-quote, or heredoc handling needs N edits — and the prior `_hcl.py` quote-escape fix (R30.9) was only applied to `block_arg_value`, not the inlined copies inside `detect_in_file`. The fix is genuinely incomplete. |
| 10 | `scripts/_catalog.py:107-191` (minimal YAML parser) | **Doesn't handle multi-line flow scalars or folded block scalars** | `- "foo\nbar"` or `key: >` (folded) or `key: \|-` (literal) aren't supported. Catalogue entries with multi-line `narrative` or `recommendation` fields work today only because they use the implicit "indented continuation" shape the parser does handle; a contributor reaching for a YAML feature outside that subset silently writes a malformed entry. |
| 11 | `scripts/_output.py:1549-1553` | **Inline urgency-ranking dict in `max` key — drift hazard** | `{"CRITICAL": 4, "HIGH": 3, ...}` defined inline in a max-key lambda. The same ranking is duplicated in 4-5 other locations in `_output.py` (compliance render, MITRE render, PR summary, score explainer). A future contributor bumping HIGH to 5 in one place but not the others gets inconsistent sort orders across surfaces. Lift to a module constant. |
| 12 | `scripts/detect.py:289-293` (locals regex) | **`(.+?)\\s*$` greedy capture eats trailing comments** | The locals-parsing regex `^\\s*([\\w-]+)\\s*=\\s*(.+?)\\s*$` captures everything to EOL including `# trailing comments`. The `block_arg_value` path strips comments quote-aware; locals don't. A `local_name = "value" # explanation` is parsed as `local_name = "value" # explanation` (with quote intact but trailing comment glued on). |
| 13 | `integrations/mcp-server/server.py:365-372` | **Mermaid render failure masked as a comment** | If `import detect` fails (sys.path miss, syntax error, missing sibling), the exception is caught and `mermaid` is set to `"# (Mermaid rendering unavailable: ...)"`. Callers receive what *looks* like valid output. A new engine seam missing from the bundle silently degrades the MCP tool's output instead of failing the request. |
| 14 | `vscode-extension/src/extension.ts:972` | **`onDidSaveTextDocument` registration unchecked** Wait — verified inside `context.subscriptions.push(...)` at line 990. **Rejected on re-read** (same as the prior audit's #10). | — |

---

## Brittleness — works today, breaks under stress

| # | File:line | Brittleness | Trigger |
|---|---|---|---|
| 15 | `scripts/check_terragoat_snapshot.py:38-41` | **`returncode > 1` lets engine exit 2 (config error) through with garbage stdout** | The script accepts exits 0 and 1 as success and then calls `json.loads(r.stdout)`. Exit 1 with empty stdout (engine crashed before emit) is caught by the R30.9 stderr fix (good), but exit 2 (config error: bad target path, missing catalogue) WOULD be caught. False alarm — re-read shows the early `if r.returncode > 1` arm raises `SystemExit`. **Rejected.** |
| 16 | `vscode-extension/scripts/bundle-engine.js:34-50` | **`MIN_SIBLING_COUNT = 15` is a magic number without rationale** | Today the repo has 18 sibling modules. If a deletion drops the count to 14, the build fails with "expected ≥ 15" — no explanation of why 15. A maintainer raising the count after legitimate consolidation has no signal whether 15 was a safety margin or a hard requirement. Add a one-line comment ("≈ current count - 3, the smallest legitimate drop"). |
| 17 | `integrations/run-task/server.py:127-132` (R30.9 fix) | **Synthetic `_scan_failed: True` field is undocumented** | The R30.9 fix injects `_scan_failed: True` into the response when JSON parse fails. The field name doesn't appear in any docstring, OpenAPI spec, or downstream consumer. A run-task client that surfaces engine output to a Slack channel renders `_scan_failed: True` as a literal — confusing to operators. Document the shape, or use a sentinel rule-id (`SYN-SCAN-FAILED`) so the existing render pipelines handle it consistently. |
| 18 | `vscode-extension/src/iframeBridge.ts:48` | **Idempotency check on sentinel comment** | The R30.9 fix replaced the `'openLink'` substring check with `<!-- tfanalyze-link-bridge-v1 -->`. Good. But a future render template that happens to inject the *exact same* sentinel comment (e.g., a third-party HTML report passing through the bridge) collides and the bridge stays absent. Tag with a CSS class on the injected `<script>` for double-confirmation. |
| 19 | `demo/app.py:113-115` (paste-and-scan) | **`json.JSONDecodeError` masks engine config errors as "invalid JSON"** | If detect.py exits with a config error (`--target missing`, bad catalogue) the captured stdout is empty and `json.loads("")` raises `JSONDecodeError`. The handler raises 500 "invalid JSON", but the real cause is the config error visible only in stderr. Operator debugging the production demo sees the wrong root cause. |
| 20 | `docs/mcp-server.md:27` | **Doc says "five tools" but server exports six** | `blast_radius_report` was added in R30.18 but the doc preamble still claims "five tools". Operator reading the README misses the newest tool. Trivial fix; flagged for completeness. |
| 21 | `integrations/badge-service/server.py:343-348` | **Grade validation asymmetric — engine-emitted invalid grade falls through** | `_GRADE_COLOURS` is checked when ingesting a scorecard, but a future engine emitting `grade: "A+"` (invalid) is persisted as-is. The badge render at line 138 falls back to neutral grey instead of failing loudly. Validate the grade at *render* too, with a fallback to "F" + error log if mismatch. |
| 22 | `scripts/gen_rule_docs.py:723, 733` | **No pre-flight check that `DOCS_RULES_DIR` exists** | A `rmdir docs/rules && touch docs/rules` (or someone replacing the directory with a file by mistake) makes `write_text` raise `IsADirectoryError` deep in the generator. Cheap: assert `DOCS_RULES_DIR.is_dir()` at startup with an actionable error. |

---

## Subagent claims rejected on re-read

Three subagent findings were demoted or rejected:

- **"`moduleReusePanel.ts` + `mitrePanel.ts` were missed in the disposable-leak fix"** — both panels are created with `enableScripts: false` (lines 30 and 54 respectively) and have **no `onDidReceiveMessage` handler at all**. There's nothing to dispose. The R30.9 fix correctly covered the four panels that have message handlers.
- **"`_attack_graph.py:269-274` duplicate edge inference"** — already fixed in R30.9; the audit doc explicitly cites the comment R30.9 added at that line.
- **"`detect.py` `atexit` closure captures a mutable reference"** — verified that `_out_file` is never reassigned after line 3568. The closure is safe.

---

## Recommended fix order

Ranked by **(severity × user impact) ÷ effort**:

1. **`detect.py` `hcl_context` block attribution fix** (1 hour). Closes #1 + #2 together. Need to track a stripped→original offset map, OR re-run the search on the original text (slower but exact). The existing fix is half-right; this completes it.
2. **`tests/helpers.py:26-29` — log + raise on JSONDecodeError** (15 min). Closes #3. Single-test driver; fix once, no caller-side change needed.
3. **`scripts/self_test.py:64-78` — surface engine crashes** (20 min). Closes #4.
4. **`integrations/github-action.yml:137-146` — try/except around JSON parse** (15 min). Closes #5.
5. **Terraform provider: compliance failure → `AddError` not `AddWarning`** (15 min). Closes #6.
6. **`_lsp.py:175` — reject `*args` callables** (10 min). Closes #7. One-line change.
7. **Promote inline urgency rank to module constant in `_output.py`** (30 min). Closes #11. Mechanical search-replace.
8. **Document synthetic `_scan_failed` shape in run-task + use a sentinel rule-id** (30 min). Closes #17.
9. **Update `docs/mcp-server.md` to list six tools** (5 min). Closes #20.
10. **Remove conditional assertions from hypothesis tests** (20 min). Closes #8.

Items 1–5 are real correctness bugs. Items 6–10 are hardening. The brace-walking duplication (#9) and YAML parser limitations (#10) remain deferred — both need a structural change (`_brace_walk` helper, PyYAML dependency or richer custom parser) that exceeds a single audit-round's scope.

---

## Structural finding

**The R30.8 + R30.9 fixes themselves introduced one new correctness bug (#1, #2 — the `hcl_context` line counting fix has a coordinate-space mismatch on block attribution).** Every fix has a chance of introducing its own bug; the structural lesson is that line-counting fixes in `detect.py` need either an offset map or a single helper that owns the stripped↔original translation. This is the same lesson the prior audits drew about `_brace_walk`: the right answer to repeated patterns in `detect.py` is to extract one helper rather than fix sites one at a time. Both #1/#2 and the existing brace-walking duplication (#9) point to the same seam — a `_text_navigator` that owns position + line + stripped-coordinate translation.

The integrations + tests audited cleaner than expected. The largest remaining surface is `_output.py` (1.7k LoC) which sampled only a handful of the duplications it almost certainly contains — and `detect_in_file` (673 LoC), which both prior audits deferred. Pulling `_brace_walk` and consolidating the urgency-rank constant in `_output.py` are the two highest-leverage structural moves before the next round.

---

## Counts

- Subagent reports returned ~38 raw findings.
- Synthesised to **22 findings** + 3 rejected on re-read.
- **6 critical, 8 high-severity smells, 8 brittleness** items.
- 2 findings cite bugs introduced by R30.8/R30.9 fixes (#1, #2).
