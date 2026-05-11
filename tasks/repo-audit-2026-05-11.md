# tf-analyze repo audit — code smells, bugs, brittleness

**Date:** 2026-05-11
**Method:** Five parallel `Explore` subagents, each owning one surface of the codebase, returning ranked findings with file:line citations. Synthesized here.

**Surfaces audited:**
- `scripts/detect.py` (4,378 LoC) — orchestrator + detection state machine
- Older engine seams: `_hcl.py`, `_attack_graph.py`, `_catalog.py`, `_scoring.py`, `_versions.py`, `_mitre.py`, `_blast_radius.py`
- R30.19 fresh extracts: `_cache.py`, `_diff.py`, `_registry.py`, `_plan_state.py`, `_apply_fixes.py`, `_baseline.py`, `_modes.py`, `_verify.py`, plus `_output.py` (1.7k LoC) and `_lsp.py`, `_threat_intel.py`
- VS Code extension TypeScript (`vscode-extension/src/`)
- Tests + CI (`tests/`, `.github/workflows/`, `vscode-extension/scripts/bundle-engine.js`)

---

## Critical bugs (real correctness risk — fix first)

| # | File:line | Risk | What breaks |
|---|---|---|---|
| 1 | `vscode-extension/src/attackGraph.ts:314` | **HTML injection / XSS** | `innerHTML` set from `d.label` + `d.findings` without escaping. A Terraform resource named `<img src=x onerror=alert(1)>` (or any unescaped engine field) executes JS in the webview. Webview has `enableScripts: true`. |
| 2 | `vscode-extension/src/extension.ts:468` | **UI freeze on hung engine** | `cp.spawn("python3", ...)` has no timeout. If detect.py hangs (Windows quirk, infinite-loop bug, huge repo), status bar and panels stay spinning forever with no escape. |
| 3 | `vscode-extension/src/extension.ts` (runScan registration paths 803/826/847/906) | **Race condition** | Concurrent `runScan` invocations: status-bar click + autosave-on-save can spawn two engines, `findingsMap.clear()` (line 493) races with the prior scan's writes. No `scanInFlight` guard. |
| 4 | `scripts/detect.py:450, 1102, 1606, 1673` | **Wrong line numbers on CRLF files** | `text.count("\n", 0, m.start()) + 1` ignores that on CRLF `\r\n` is 2 bytes but 1 line. Mixed-ending checkouts (Windows contributors, mis-configured `core.autocrlf`) get every finding's line number wrong. |
| 5 | `vscode-extension/src/extension.ts:231, 495`; `moduleReusePanel.ts:135` | **Broken on Windows** | `f.file.startsWith("/")` and `h.file.split('/')` assume Unix paths. Engine emits backslashes on Windows → check fails → paths resolved incorrectly. Use `path.isAbsolute()` / `path.normalize()`. |
| 6 | `scripts/_modes.py:161`; `scripts/_threat_intel.py:216` | **IndexError crashes** | `parts[1]` after `line.split(" ", 1)` and `row[1]` from CSV reader, both without bounds checks. Malformed git output or truncated EPSS CSV → unhandled exception. |
| 7 | `scripts/_apply_fixes.py:188-189` | **`IsADirectoryError` regression risk** | Comment acknowledges the issue but the `is_file()` filter doesn't cover every path; a directory matching the filename pattern still slips through. Old bug; not all gaps closed. |
| 8 | `scripts/_threat_intel.py:228`, `_diff.py:38`, `_registry.py:57-61` | **Network/IO failures uncaught** | gzip decompression errors not caught in EPSS loader; `stat().st_mtime` after `glob()` crashes if file deleted between calls; 5s registry timeout with no retry → single slow response stalls scan. |

### Suspect finding flagged but NOT included as a bug

- `_blast_radius.py:66-72` — Subagent claimed "DFS stack overflow on deep chains." On inspection this confuses iterative `stack.pop()` (list method, no recursion) with Python's call-stack limit. Iterative BFS/DFS on a list has no stack risk; only memory pressure. **Not a real bug.** Filed here for the record so it's not re-raised.

---

## High-severity code smells

| # | File:line | Smell | Why it matters |
|---|---|---|---|
| 9 | `scripts/detect.py:375-1048` | **`detect_in_file` is a 673-LoC god function** | 12 pattern-kind branches, each reimplementing brace-depth walking (lines 605-617, 633-646, 700-712, 862-875, 956-971, 1089-1097). Copy-paste bugs in depth tracking are guaranteed; the IAM statement off-by-one (line 674, see #11) is exactly this shape. Extract a shared `_brace_walk()` helper. |
| 10 | `scripts/detect.py:1342-1596` | **`detect_corpus` is a 254-LoC function with 8 elif arms** | `module_unused` builds two dicts (`referenced_dirs`, `module_like_dirs`) with overlapping path-resolution logic. `cross_module` (1440-1474) doesn't catch the OSErrors that `module_unused` (1572-1574) does — inconsistent failure modes. |
| 11 | `scripts/detect.py:674` | **Off-by-one in IAM statement line attribution** | `body[:sm.start()].count("\n")` is relative to the wrong substring; reports incorrect line numbers in `iam_policy_analysis` findings. Companion to #9. |
| 12 | `scripts/_output.py:1715-1750` + (722-780, 1430-1473, 1663-1710) | **1.7k-LoC module with CSS scattered across f-strings** | Adding an urgency colour requires touching 10+ locations. `URGENCY_RANK` defined twice (lines 1048, 1182) — drift hazard. |
| 13 | `vscode-extension/src/extension.ts:432` | **`runScan` takes 9 positional params** | Every command-handler call-site (lines 797, 821, 842, 874, 892, 917) re-types them. Parameter-object refactor. |
| 14 | `vscode-extension/src/remediationPanel.ts:54`, `compliancePanel.ts:71`, `deltaPanel.ts:76` | **`cp.execFile` boilerplate copy-pasted** | Each panel reimplements spawn + error handling. One shared `_runEngine(mode, callback)` would eliminate the bug surface. |
| 15 | `scripts/detect.py:2764, 3831, 3872, 3882, 3889, 3906` | **`getattr(args, "x", default)` masks missing argparse wiring** | A rename typo (`--state_json` vs `--state-json`) silently returns the default instead of failing fast. Use direct attribute access; argparse-managed `Namespace` always has the attribute if you wired it. |
| 16 | `scripts/_hcl.py:195-256` | **`find_blocks` and `find_simple_blocks` are near-duplicate brace-balancers** | Identical brace-balance loops with different output dict keys. Extract a shared `_find_blocks_by_depth` helper. |
| 17 | `scripts/_attack_graph.py:133-177` | **23 hand-written regex constants without abstraction** | `_INET_*` (9) + `_EDGE_*` (14) regex pairs for each resource type × attribute combination. No docstring explains why a given pattern uses `re.DOTALL` or matches two prefixes in one regex vs. two regexes. Future maintainers can't tell if a missing pattern is intentional or a miss. |

---

## Brittleness — works today, breaks under stress

| # | File:line | Brittleness | What triggers it |
|---|---|---|---|
| 18 | `scripts/_hcl.py:310-333` | **`block_arg_value` quote tracking ignores `\"` escapes** | Toggles `in_dq`/`in_sq` without checking for backslash. `key = "foo \"bar\""` returns corrupted value. |
| 19 | `scripts/_catalog.py:155, 164` | **Minimal YAML parser splits on first `:` without quote awareness** | A catalogue entry like `- name: "aws:iam:role"` parses `"aws` as the key and `iam:role"` as the value. Same parser is the *only* source for catalogue rules — corruption is silent. |
| 20 | `scripts/detect.py:605-653, 699-725` | **`iam_policy_analysis` + `helm_set_value` brace-walking breaks on heredocs / multi-line lists** | Walks `{` and `}` without tracking string state. A heredoc containing `}` in plain text, or a multi-line list with `=` inside, corrupts block boundaries. |
| 21 | `scripts/detect.py:999-1001, 1029` | **`source_regex: ".*"` and `name_regex: ".*"` defaults silently over-match** | Missing `source_regex` in a catalogue entry doesn't error — it matches every module. Should require explicit pattern. |
| 22 | `scripts/_versions.py:96, 106` | **Single-element constraint `~> 3` silently skipped** | Length check at 96 bypasses the whole clause. False negatives in version-gated rules. |
| 23 | All R30.19 modules (`_lsp.py:136-137`, `_modes.py:48-50`, `_verify.py:82-83`, `_baseline.py`, `_apply_fixes.py`, `_plan_state.py`) | **Callable-injection signatures undocumented** | Wrong signatures from detect.py pass typecheck, fail at first invocation. Add docstring contracts and assert callable signatures at module-load. |
| 24 | `scripts/_cache.py:104-108` | **mtime staleness with no clock-skew handling** | Clock-skew (system clock backwards, NTP correction) → "future" mtime stays fresh forever. |
| 25 | `scripts/_baseline.py:70-84` | **Suppression expiry parses `YYYY-MM-DD` only; error message doesn't say so** | User writes `expires: 01/01/2027` → silent date-parse error → not suppressed → confused user. |
| 26 | `scripts/_attack_graph.py:357` | **Magic threshold `if len(node_list) > 60`** | Pruning triggers at 60 without docstring rationale. 65-node repo gets truncation; 500-node repo cliffs into different behavior. |
| 27 | `scripts/_scoring.py:38-43` | **Risk weights are unexplained numbers** | `CRITICAL=15, HIGH=7, MEDIUM=3, LOW=1` — why these? Bumping any breaks user-pinned compliance gates with no signal. Lock with a `_SCORING_VERSION` and changelog. |
| 28 | `scripts/detect.py:265-353` | **`_extract_var_defaults_by_dir` mixes 4 concerns in 88 LoC** | variable defaults + locals + AWS `default_tags` + module flow-through all in one function. Multi-line locals values are truncated by the greedy `(.+?)` regex (line 292). |
| 29 | `scripts/detect.py:418` | **Glob-match exception fallback hides catalogue errors** | `try: file_path.match(glob) except Exception: fallback = endswith(...)`. A malformed glob `**/*.tf[` is silently treated as no-match instead of raising. |
| 30 | `vscode-extension/src/attackGraph.ts:75` | **`cp.exec` with template-literal command (injection risk)** | `` `python3 "${absScript}" --target "${wsFolder}" ...` `` — if workspace path contains backticks or double-quotes, command injection. Use `cp.execFile('python3', [...args])`. |

---

## Test and CI gaps (the rails are missing)

| # | File:line | Gap | Concrete test that closes it |
|---|---|---|---|
| 31 | `.github/workflows/ci.yml:25` | **CI runs 3 of 46 test files** | Replace `pytest test_detection_core.py test_attack_graph.py test_clean_fixtures.py` with `pytest tests/`. **Single highest-ROI fix in the repo.** |
| 32 | `.github/workflows/ci.yml` | **No `npm test` step; extension node:test never runs in CI** | Add `vscode-extension && npm ci && npm test` job. The blast-radius regression fixed in v0.1.44 would have shipped without this. |
| 33 | (every catalogue entry without `fixtures:`) | **235 of 238 rules have no fixture coverage** | Self-test silently returns empty for fixture-less rules. Add a CI check: "every rule must have ≥1 fixture or an `applies_when: never_test` opt-out". |
| 34 | `.github/workflows/ci.yml` | **Python version matrix is `3.12` only** | `pyproject.toml` says `>=3.10`. Add matrix `[3.10, 3.11, 3.12, 3.13]`. |
| 35 | `tests/test_public_scanner.py`, `test_mcp_server.py`, `test_badge_service.py` | **Mock-only — no real engine roundtrip** | Add one end-to-end test per surface that spawns `python3 detect.py` against `fixtures/attack_graph_demo/` and asserts JSON shape. Same gap that hid the blast-radius bug. |
| 36 | `tests/test_rule_docs.py` (docstring) | **"byte-identical output" claim is unasserted** | `detect.py` never calls `json.dumps(..., sort_keys=True)`. Either fix the engine to sort, or drop the claim. Add a determinism test: run scan twice, `diff` the JSON. |
| 37 | `vscode-extension/scripts/bundle-engine.js` (smoke test) | **Bundle smoke test runs only at release, not in CI** | A new `scripts/_foo.py` missed from `ENGINE_SIBLING_FILES` ships broken. Add `npm run bundle-engine` to CI. |
| 38 | `.github/workflows/ci.yml:117-127` | **Hard-coded terragoat finding bounds (60-110, 90-150, 70-120)** | Drifts every ~10 rules. Replace with a snapshot file checked into the repo (`tests/snapshots/terragoat.json`) regenerated on each release. |
| 39 | Branch protection | **No required-status-checks; `auto-merge` fires before CI** | Already documented in memory (round 28 summary). Operator-only fix in repo Settings → Branches. |
| 40 | `tests/test_public_scanner.py:63`, `scripts/self_test.py:63` | **stderr swallowed; engine crashes hidden** | `subprocess.run(..., capture_output=True)` ignores `stderr`. Add an assertion: if stderr contains "Traceback" or "ERROR", fail loudly. |
| 41 | (nothing) | **No property-based tests for `_blast_radius.py` cycle handling** | `tests/test_blast_radius.py` uses hand-built synthetic graphs only. Add `@hypothesis` strategies that generate random DAGs and assert traversal determinism. |

---

## Recommended fix order

Ranked by **(severity × user impact) ÷ effort**:

1. **CI fix: `pytest tests/` instead of three named files** (15 min). Single highest-leverage change. Stops the next regression of this class from shipping.
2. **Extension XSS fix in `attackGraph.ts:314`** (30 min). Active vulnerability; webview has scripts enabled.
3. **Add `npm test` to CI** (15 min). Closes the gap that hid the blast-radius bug.
4. **`runScan` concurrency guard + 120s timeout** (45 min). One flag + one `setTimeout` + reject path. Eliminates two bugs (#2, #3) at once.
5. **Replace `getattr(args, ...)` with direct attribute access in `detect.py`** (1 hour). Eight call-sites; mechanical.
6. **Add `sort_keys=True` to JSON output OR drop the determinism claim** (10 min OR doc edit). Active correctness gap with a documented contract.
7. **Document callable-injection contracts in R30.19 modules** (2 hours). Add a runtime `inspect.signature(callback)` assertion at module entry for each of the 8 fresh extracts.
8. **Extract `_brace_walk()` helper, refactor IAM + helm + statement detectors to use it** (half-day). Fixes #9, #11, #20 in one go; eliminates the duplicated brace-tracking bug surface entirely.
9. **CRLF-aware line counting** (2 hours). One helper, search-replace at four sites in `detect.py`.
10. **Python version matrix in CI** (30 min). Matrix expansion.

Items 1–3 are essentially "edit one CI file and one .ts file" — half a day's work and eliminates the largest classes of risk in the repo. Items 4–6 are the next tier. Everything below 10 is real but lower priority.

---

## The structural finding

The test pyramid is correctly **shaped** (lots of unit tests, some integration, a few end-to-end), but **the wiring between layers is what's missing** — and that's exactly the gap that produced the blast-radius bug fixed earlier today. Mock-shaped tests on both sides of a seam don't catch seam-wiring regressions. Every consumer panel needs at least one test that runs the actual engine with the actual extension args and asserts the JSON shape the panel depends on.

The other structural pattern: **`detect.py` is mid-decomposition.** R30.0.6 → R30.19 took it from 8,441 LoC to 4,378 (-48%). The remaining 4,378 LoC are not "what's left over" — they're **the parts that resist decomposition because they share mutable state**. `detect_in_file` and `detect_corpus` together are 32% of the file. The duplicated brace-walking and the off-by-one (#11) live there because no clean seam has been pulled out yet. Recommended seam to pull next: a `_brace_walk(text, start_pos) -> (end_pos, depth_trace)` helper, then refactor the 8 brace-walking sites to use it. That's the same "mechanical pattern" that made R30.19 land 8 extracts in one round.

---

## Methodology notes

- Each subagent owned ~3-12 files and was constrained to 800-1000 words and "file:line citations for every finding."
- 5 parallel subagents returned ~70 raw findings; synthesized to 41 here after deduplication.
- One claimed bug (`_blast_radius.py` "stack overflow") was rejected on inspection — Python list `pop()` is not function-call recursion.
- This audit did not exhaust every file. `_output.py` (1.7k LoC) was sampled, not fully read; deeper rendering-format bugs may exist.
- No security findings (the tool's job). No performance findings unless egregious. No stylistic preferences.
- Subagent reports kept ranked-by-severity; this synthesis re-ranked by **fix-order ROI**, not pure severity.
