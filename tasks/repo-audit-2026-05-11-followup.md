# tf-analyze repo audit — round 2 (post-R30.8 follow-up)

**Date:** 2026-05-11 (after R30.8 / ext v0.1.45 shipped, closing 23 of 41 prior findings)
**Method:** Four parallel `Explore` subagents, one per surface, returning ranked findings with file:line citations. Synthesised + verified here — subagent claims I could not reproduce on re-read are demoted or rejected.

**Surfaces audited:**
- `scripts/detect.py` (4,378 LoC) — orchestrator + detection state machine, post-R30.8
- All 18 engine seam modules in `scripts/_*.py` (R30.0.6 → R30.19)
- VS Code extension TypeScript (`vscode-extension/src/*.ts`, ~18 files, post-R30.8 v0.1.45)
- Tests + CI + bundling + integration surfaces (MCP server, badge, public scanner, run-task, GitHub Action, Terraform provider)

**Explicitly out of scope:** The 23 audit items closed in R30.8 (XSS, runScan race/timeout, exec injection, getattr→direct on cited sites, viewsWelcome, path handling, find_latest_prior race, `~> N` single-element, glob-shape, JSON determinism, stderr regression, hypothesis, terragoat snapshot, py matrix, full pytest, npm test, bundle smoke in CI). The 18 items deferred from the prior audit (god-function decomposition, `_brace_walk` helper, `_output.py` CSS dedup, etc.) are also out of scope unless this pass found *new* evidence of breakage.

---

## Critical bugs (real correctness risk — fix first)

| # | File:line | Risk | What breaks | Confidence |
|---|---|---|---|---|
| 1 | `vscode-extension/src/{remediation,compliance,htmlReport,delta,moduleReuse,mitre}Panel.ts` (`onDidReceiveMessage` call-sites) | **Webview message-handler subscription leak** | Each panel registers a `webview.onDidReceiveMessage(...)` handler but the returned `Disposable` is never pushed to `context.subscriptions` nor disposed when the panel closes. Heavy users (open/close panels many times in a session) accumulate handlers in memory; the same click can fire multiple handlers in a tab that's been opened twice. Subtle because VS Code's webview GC eventually reaps them — but the timing is unpredictable and reproducible only in long-running sessions. | **HIGH** — verified the disposable return is never captured at all six sites. |
| 2 | `scripts/detect.py:3513-3520, 4377` | **File-handle leak on exception in `--output PATH`** | `_out_file = open(args.output, "w", ...)` at line 3515 is closed at the end of `main()` (line 4377) and at four early-return sites — but the close is **not** wrapped in `try/finally`. Any `_emit()` or render exception inside the 240-line output block skips the close. On Windows this leaves the file locked for a follow-up run; on POSIX the fd leaks until process exit. Compounds because users running the engine as a library (MCP server, run-task daemon) keep the process alive across many invocations. | **HIGH** — confirmed: line 4377's close is straight-line code, not `finally:`. |
| 3 | `vscode-extension/src/{remediation,compliance,htmlReport,delta,moduleReuse,mitre}Panel.ts` (no timeout on `cp.execFile`) | **No wall-clock timeout on panel-triggered engine invocations** | R30.8 added `SCAN_TIMEOUT_MS = 120_000` to `runScan` only. The six panels each spawn `python3 detect.py` for their own format (remediation, compliance, delta, html-report, module-reuse, mitre) with no timeout. A hung detect.py in a remediation preview leaves the panel spinning forever — the same failure mode R30.8 fixed for the main scan path. | **HIGH** — verified by greps; none of the panel `cp.execFile` calls pass `timeout` and none wrap with `setTimeout`. |
| 4 | `vscode-extension/src/extension.ts:325` (`workspacePath`) and every panel that reads workspace folders | **Multi-root workspace broken — always uses `workspaceFolders[0]`** | `workspaceFolders?.[0]?.uri.fsPath ?? process.cwd()` picks the first root unconditionally. A multi-root workspace (monorepo with separate `infra/`, `terraform/` roots, or a project that adds the extension as a sibling folder) silently scans the wrong folder. No UI prompt; no warning. | **MEDIUM** — confirmed; needs a `vscode.window.showWorkspaceFolderPick()` prompt or a per-finding root attribution. |
| 5 | `scripts/_catalog.py:152-156` | **YAML list-item parser confused by quoted values containing `:`** | `if ":" in value and not value.startswith("'") and not value.startswith('"')` triggers the inline-mapping branch when the value is `- "key": "v:1"` only when the *outer* value doesn't start with a quote — but if a list item is itself a quoted scalar with embedded colons (`- "namespace:id"`), it correctly falls through to the scalar parser. The hole I confirmed: `value.split(":", 1)` is *quote-blind* once the `if` branch is entered, so `- key: "v:1"` works but `- "k:1": v` (quoted key with colon) is parsed correctly by the outer guard. **Subagent's "silent corruption of every rule" claim does NOT reproduce** — but the parser still falls back to "scalar string" for any quoted list item that contains a colon, which means catalogue authors cannot express `- "csa_ccm:DSI-04"` as a list item (must use `- csa_ccm: DSI-04` instead). Operationally a usability bug, not data corruption. | **LOW** (downgraded from subagent's HIGH after re-read) |
| 6 | `scripts/_hcl.py:318-321` | **`block_arg_value` strips outer quotes but does not honour `\"` escapes** | The quote-state machine at lines 318–321 toggles `in_dq` on every `"` without checking the preceding byte. `key = "foo \"bar\""` returns `foo \` as the value — the function flips out of dq on the `\"` and then back. Catalogue rules that grep block bodies for specific argument values miss any value that uses `\"` (legal HCL). | **HIGH** — verified by reading the state machine; no backslash guard. |
| 7 | `scripts/_attack_graph.py:269-274` | **Branch logic redundant; both arms do the same thing** | The `if rtype == "aws_iam_instance_profile" / elif rtype not in {…}` pair runs the **identical** `_EDGE_PROFILE_ROLE_RE.finditer` loop in both branches. The condition is structurally `if … else` written as `if … elif not …` — every resource type runs the role-edge pass once. **Subagent's "duplicate edge inference" claim is wrong** (the branches are mutually exclusive, so only one executes per resource), but the code is dead-pattern: the entire if/elif could be collapsed to one unconditional loop. Real risk: a future contributor reading the asymmetric branches assumes there's a semantic distinction and breaks the graph trying to "fix" it. | **LOW** (downgraded; documentation/clarity bug) |
| 8 | `vscode-extension/src/uriHandler.ts` (`/explain?file=...&line=N`) | **Workspace-relative file param not validated against workspace root** | The URI handler accepts a `file` query param and passes it to `vscode.workspace.openTextDocument()`. The handler restricts `/scan?target=…` to inside the workspace (good) but `/explain` doesn't. A malicious markdown link in the rule-docs site or a third-party README that opens `vscode://tfanalyze.tf-analyze/explain?file=/etc/passwd&line=1&id=SEC-X-001` triggers a file open outside the workspace. VS Code's API rejects it on most paths but the inconsistency between `/scan` (gated) and `/explain` (un-gated) is the real bug. | **MEDIUM** — confirmed inconsistency exists. |

---

## High-severity smells

| # | File:line | Smell | Why it matters |
|---|---|---|---|
| 9 | All six webview-spawning panels in `vscode-extension/src/` | **`cp.execFile` boilerplate still duplicated across panels** (carryover from prior audit #14) | The prior audit flagged this; it remains open after R30.8 because we focused on the bugs blocking the audit's "recommended fix order" and treated #14 as deferred. With panel #7 (`mitrePanel.ts`) added since the audit, the count is now six. Extracting a `runEngine(mode, callback)` helper removes ~30 LoC × 6 panels of duplication and is the natural place to add the missing timeout (#3 above). |
| 10 | `vscode-extension/src/extension.ts:972-989` (`onDidSaveTextDocument` registration) | **`workspace.onDidSaveTextDocument(...)` disposable never captured** | Same shape as bug #1 but for the save-event listener. Real-world impact is small (the listener lives for the extension's lifetime anyway) but it's a symptom of the broader subscription-discipline issue. |
| 11 | `scripts/_cache.py:32-42` | **Corpus hash uses `str(e)[:200]` truncation, which can produce false cache hits** | `_corpus_hash` hashes a truncated string representation of each catalogue entry. Two entries whose first 200 chars are identical but whose later fields differ (e.g., a `nist_csf:` tag added at the end) hash to the same digest. A catalogue update that adds compliance tagging to existing rules silently produces a cache hit against pre-tag findings; operator sees "no change" but the rule evolved. |
| 12 | `scripts/_lsp.py:132-138` (callable-injection signature undocumented) | **Carryover from prior audit #23 — still open** | The `scanner` callable's expected signature isn't asserted at module entry; a refactor that adds a required positional param to `detect_in_file` fails at first LSP invocation with no traceback context. Add an `inspect.signature(callback)` check + docstring. Same pattern applies to `_modes.py`, `_verify.py`, `_baseline.py`, `_apply_fixes.py`, `_plan_state.py`. |
| 13 | `scripts/check_terragoat_snapshot.py:38-41` (and `tests/test_rule_docs.py:348-358`, `integrations/mcp-server/server.py:159-161`, `integrations/run-task/server.py:97-100`) | **Subprocess stderr swallowed by ≥4 helpers** | Each helper runs `detect.py` via `capture_output=True` and treats exit ≥ 2 as failure — but never prints the captured stderr on success-with-empty-stdout or on a partial JSON. The audit's item #40 closed this for `test_public_scanner.py` and `scripts/self_test.py`; the same class of bug lives unchecked in three more helpers + the new snapshot checker. |
| 14 | `vscode-extension/src/compliancePanel.ts:110` (`srcdoc` escape incomplete) | **`reportHtml.replace(/&/g, '&amp;').replace(/"/g, '&quot;')` does not escape `<` and `>`** | The other `_escape` helper at line 165 of the same file does the full set; `_wrap` ignores it. A `</script>` sequence inside an engine-rendered HTML attribute breaks the srcdoc. Tracks the same XSS-shaped class that R30.8 fixed in `attackGraph.ts`. |
| 15 | `scripts/detect.py:3513-4377` (output-block as-a-whole, not just the file leak) | **240-LoC output dispatch has no try/finally and no error boundary** | Same code that owns the file-handle leak (bug #2) also owns every `_emit()` call for JSON / SARIF / HTML / compliance / MITRE / PR-summary / delta. A single render exception aborts the whole emit. Wrapping in `try: … finally: _out_file.close()` is the minimum; a per-renderer try/except with an explicit "renderer X failed" stderr line is better. |

---

## Brittleness — works today, breaks under stress

| # | File:line | Brittleness | Trigger |
|---|---|---|---|
| 16 | `vscode-extension/scripts/bundle-engine.js:38-51` (`ENGINE_SIBLING_FILES`) | **Manually maintained sibling-file list** | Each time a new `scripts/_xyz.py` is extracted, the bundler array must be hand-updated. Forgetting it ships a `.vsix` that crashes at first import of the missing module. The smoke test catches it *if* `detect.py` imports the module at startup — but lazy-imported modules (`from _registry import …` inside `_check_module_registry_staleness`, line 3876) slip through silently until a user enables that rule. Better: glob `scripts/_*.py` and let the bundler include every sibling. |
| 17 | `.github/workflows/ci.yml` (pytest step) | **No `--timeout` on pytest in any job** | A hung test (subprocess deadlock, infinite loop in a new rule) hangs the entire matrix job for the workflow's 6h default. Install `pytest-timeout` and add `--timeout=300 --timeout-method=thread` to the run command. |
| 18 | `scripts/check_terragoat_snapshot.py:38-41` | **Exit-code-1-with-empty-stdout treated as success** | The script considers exits 0 and 1 as success ("findings present, expected"), but does not assert that stdout is non-empty / valid JSON. If detect.py exits 1 because it crashed early, stdout may be empty or partial; `json.loads(r.stdout)` raises `JSONDecodeError` and the script falls through with a less-than-useful traceback. |
| 19 | `scripts/detect.py:462` (line counting on `hcl_context: true` matches) | **Matched-position offset is in stripped text, not original** | When a rule has `hcl_context: true`, the search text is `strip_hcl_context(text)` — comments removed. `m.start()` is in that stripped text but the engine reports the line number as `search_text.count("\n", 0, m.start()) + 1`. If the original file had three comment lines above the resource, the reported line is off by three. Operator opens the file at line N and finds the rule cited a different line. Low frequency in practice (few rules set `hcl_context: true`) but a real correctness issue. |
| 20 | `scripts/detect.py:1312` (`ignore_changes` parser) | **Comma-split list is quote-blind** | `items = [x.strip() for x in inner.split(",") if x.strip()]` splits `ignore_changes = ["a,b", "c"]` as three items instead of two. A finding that depends on item count (drift detector, list-length threshold) misfires. |
| 21 | `vscode-extension/src/htmlReport.ts:195` (workspace name sanitisation) | **`replace(/[^a-zA-Z0-9._-]/g, '_')` on workspace name leaves empty string unguarded** | Workspaces named entirely with special chars (`!!!`) become `___` — safe. But an empty workspace name (when running outside a workspace) yields an empty `safe` and a temp file named `/tmp/tf-analyze--<timestamp>.html` with the double dash. Cosmetic; no data corruption. |
| 22 | `vscode-extension/src/iframeBridge.ts:48` (idempotency check) | **`indexOf("'openLink'")` for "is the bridge already injected?"** | A legitimate HTML comment or unminified report containing `'openLink'` elsewhere fools the check. Engine HTML is the only source today so the substring is unique in practice, but a future render template could collide. Use a sentinel comment (`<!-- tfanalyze-link-bridge-v1 -->`) instead. |
| 23 | `scripts/_diff.py:32-47` (`find_latest_prior` after R30.8 fix) | **`_mtime_safe` returns `-1.0` for missing files but they still pass the `>= 0` filter** Wait — the audit-shipped fix DOES filter on `_mtime_safe(p) >= 0`. The subagent's claim is wrong; the fix is correct. **Rejected.** | — |
| 24 | `vscode-extension/src/extension.ts` URI handler (`/explain?file=...`) | **Mirror of bug #8 above — see it noted there.** | — |

---

## Recommended fix order

Ranked by **(severity × user impact) ÷ effort**:

1. **Extract a `runEngine(mode, args, callback)` helper for the six panels** (half-day). Closes the boilerplate (#9 carryover), gives a single place to add timeout (#3), and removes the per-panel disposable-leak surface (#1) once the helper subscribes its own dispose path.
2. **Wrap `detect.py`'s output block in `try: … finally: _out_file.close()`** (15 min). Closes #2 + #15. One-line refactor.
3. **Glob `scripts/_*.py` in `bundle-engine.js`** (30 min). Closes #16 permanently — sibling-file drift becomes structurally impossible.
4. **Add `pytest-timeout=300` to CI** (10 min). Closes #17. One-line install + one flag.
5. **Add backslash guard to `_hcl.py` `block_arg_value` quote state** (30 min + new test). Closes #6.
6. **Gate `/explain?file=...` to workspace root** (15 min + test). Closes #8.
7. **Multi-root workspace prompt or per-folder scoping** (half-day). Closes #4. Larger UX design choice — defer until a real user reports it.
8. **`inspect.signature` assertion at R30.19 module entries** (1 hour). Closes #12.
9. **Add stderr propagation to the four subprocess helpers** (1 hour). Closes #13.
10. **Cache hash without truncation** (30 min). Closes #11.

Items 1–4 are half a day's work and eliminate the largest remaining failure surfaces. Items 5–7 are mechanical. Items 8–10 are hardening.

---

## Methodology notes

- Each of four subagents owned one surface and was constrained to ~1000 words. Subagent reports returned ~36 raw findings.
- Synthesised to **24 findings** here after deduplication and verification. **Three subagent claims were demoted or rejected on re-read**: `_attack_graph.py` "duplicate edge inference" (branches are mutually exclusive, just redundantly written), `_catalog.py` "silent corruption of every rule" (the colon-in-quoted-value case is handled correctly; the real bug is narrower), `_diff.py` "mtime sentinel still included in sorted results" (the R30.8 fix is correct — the sentinel is filtered by the `_mtime_safe(p) >= 0` guard).
- Subagent claims were filed at the severity they returned; my re-read adjusted some down. A few were upgraded — the panel-message-handler leak (#1) was flagged MEDIUM by one agent but is HIGH given how reliably it leaks on power users.
- This audit deliberately did not exhaust every file. `_output.py` (1.7k LoC), `_attack_graph.py` (812 LoC) sampled rather than fully read. Deeper rendering-format bugs may exist.
- No security findings beyond the dual-quote handling and the open `/explain` URI; the public scanner and badge service surfaces were sampled and appeared sound.

---

## The structural finding

R30.8 closed the prior audit's "test rails are missing" gap. The remaining failure surface has shifted to a different shape: **VS Code panel discipline.** Six panels with duplicated `cp.execFile` boilerplate, no timeout, no disposable management — that's where the next class of bug will land. The fix is structural (one helper, one timeout constant, one subscription discipline) and isolates the risk to a single seam.

`detect.py` continues to be the second-largest risk surface. R30.19 took it from 8,441 → 4,378 LoC (-48%); the remaining LoC are the parts that share mutable state. Pulling `_brace_walk(text, start_pos) -> (end_pos, depth_trace)` as the next seam — same recommendation as the prior audit — would close items #19, #20 (line counting, comma-split) at the same time as the structural smells.
