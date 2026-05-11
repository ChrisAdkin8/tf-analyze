# tf-analyze repo audit — round 4 (post-R30.10 + ext v0.1.47)

**Date:** 2026-05-11 (after R30.10 / ext v0.1.47 shipped, closing 20 of 22 round-3 findings)
**Method:** Four parallel `Explore` subagents on surfaces with the least prior attention; ~40 raw findings synthesised + verified here.

**Surfaces audited:**
- `_output.py` exhaustive read (1.7k LoC; only sampled in rounds 1-3)
- `_attack_graph.py` (812 LoC) + `_threat_intel.py` + `_mitre.py` (briefly read before)
- `detect_in_file` (673 LoC, 12 pattern-kind branches) + `detect_corpus` (254 LoC) + `_extract_var_defaults_by_dir`
- Catalogue YAML schema + docs generators + regression-of-fix on R30.10 changes

**Explicitly out of scope:** Everything closed by the three prior audits (~60 findings). 5 items deferred to standalone structural PRs (`_brace_walk` extraction, `_output.py` CSS dedup, `_catalog.py` multi-line scalars, `detect_in_file` god-function, `_attack_graph.py` regex rationale comments).

---

## Critical bugs (real correctness risk — fix first)

| # | File:line | Risk | What breaks | Confidence |
|---|---|---|---|---|
| 1 | `scripts/_output.py:768, 1605-1607` | **HTML report XSS via unescaped rule titles + finding IDs** | The executive view (line 768) injects `f['id']` and `entry.get('title','')` raw into HTML. The findings panel (1605-1607) does the same with `display_urgency`, `docs_url`, `eid`, `title`. A custom-catalogue rule with `title: "AWS S3 <img onerror=alert(1)>"` executes JS in any browser opening the rendered report. This is the SAME class the R30.8 fix closed in the VS Code attack-graph webview — but `_output.py` was never re-audited for the same shape. | **HIGH** — direct read of the f-strings; no `html.escape` anywhere on the path. |
| 2 | `scripts/_output.py:703-709, 1566` | **HTML report XSS via narrative templates with finding-supplied resource names** | `template.format(resource=resource or rule_id, file=file or "unknown file")` interpolates finding fields into the narrative template, which is then injected raw into HTML. A resource named `aws_s3_bucket.<script>alert(1)</script>` propagates through the narrative and into the rendered report unescaped. Worse: a resource name containing `{foo}` triggers a second `.format()` interpretation (placeholder confusion). | **HIGH** — confirmed by reading the two-stage interpolation. |
| 3 | `scripts/_attack_graph.py:797-810` | **Standalone HTML attack-graph sidebar XSS via `innerHTML` from unescaped fields** | The Python-generated standalone HTML report (separate from the VS Code extension's `attackGraph.ts`, which R30.8 fixed) builds the sidebar via `html += '<b>File:</b> <code>'+n.file+'</code>:'+n.line+'<br>'`. A node `file` or `type` containing `</code>` or HTML breaks out. The R30.8 fix only touched the TypeScript file in the extension — this Python equivalent was missed. | **HIGH** — confirmed by reading lines 798-810; no escape on `n.file`, `n.type`, `n.findings[i]`. |
| 4 | `scripts/_attack_graph.py:474-476` | **`_mermaid_id` lossy on `.` vs `-` collisions** | `addr.replace(".", "_").replace("-", "_")` collapses both characters to the same byte. `aws_iam_role.foo`, `aws_iam.role-foo`, and `aws-iam_role_foo` all become `aws_iam_role_foo` — three distinct resources render as one node in the Mermaid diagram. Operators misread the topology. | **HIGH** — direct read; one-line replacement is genuinely lossy on real catalogue inputs. |
| 5 | `scripts/_attack_graph.py:320` | **Duplicate `INTERNET → sg` edges inflate centrality scoring** | The `internet_via_sg` propagation loop appends `{"from": "INTERNET", "to": src, …}` for every reachable security-group edge, with no dedup. A resource referencing two SGs (typical for EKS / multi-AZ ALB) gets two `INTERNET → resource` edges. Downstream centrality scoring counts both and over-weights the resource. | **MEDIUM** — read the propagation loop; deduplication missing. |
| 6 | `scripts/detect.py:1513` | **`cross_module` lacks OSError handling that `module_unused` has** | `(caller_dir / src).resolve()` at 1513 has no try/except. The same operation 100 lines below in `module_unused` (around 1644-1647) is wrapped in `try: … except (OSError, ValueError):`. A module source containing a symlink loop, non-existent component, or permission error crashes `cross_module` while `module_unused` silently skips — same scan, same input, different outcomes. Prior audit's #10 flagged this; still open. | **HIGH** — side-by-side read confirms the divergence. |
| 7 | `scripts/detect.py:357-373` (`_extract_var_defaults_by_dir` module-flow path) | **Quote-blind comment strip in module-flow-through path** | The locals branch of the same function (lines 287-314) uses an escape-aware quote walker for trailing comments (R30.10 fix); the module-flow branch 50 lines below still uses the old `re.sub(r'\s*#.*$', '', raw)` which strips everything from `#` onward regardless of quote state. A module call with `count = "value # not a comment"` loses the trailing payload. The fix exists 50 lines away in the same function — copy-paste miss. | **MEDIUM** — direct read; the fix from R30.10 only patched the locals branch. |
| 8 | `integrations/run-task/server.py:137` | **R30.10 `SYN-SCAN-FAILED` synthetic finding uses an invalid `section`** | The synthetic finding declares `"section": "engine"` but `_catalog._VALID_SECTIONS` is `{"security", "robustness", "dry", "style", "simplicity", "ops", "cicd", "module", "module-reuse", "stack", "verification"}` — `"engine"` isn't in the set. A downstream renderer that validates against `_VALID_SECTIONS` rejects or misclassifies the synthetic finding. The R30.10 fix introduced this. | **HIGH** — verified by grepping `_VALID_SECTIONS`; "engine" is not present. |

---

## High-severity smells

| # | File:line | Smell | Why it matters |
|---|---|---|---|
| 9 | `scripts/_output.py:763, 1485` | **Urgency-colour dicts duplicated across 2-3 sites** | The urgency *rank* was consolidated in R30.10 (`URGENCY_RANK_ASCENDING/DESCENDING`). The urgency *colours* — `{"CRITICAL": "#7b0000", "HIGH": "#b02a2a", …}` — are still defined inline at the executive view (line 763) and the fix-priority table (line 1485). A future re-theme touching only one site produces inconsistent badges across surfaces. Apply the same lift as the rank: `_URGENCY_COLOURS = {…}` at module top. |
| 10 | `scripts/detect.py:634-728, 747-773, 807-824, 885-906, 987-1003` (12 branches) | **12 detector branches duplicate brace/paren-depth walking; no string-state tracking** | The prior audit's #9 flagged this and deferred to `_brace_walk` extraction. Re-read confirms NONE of the branches track string state — a multiline heredoc containing `}` in plain text or an IAM policy ARN like `arn:aws:s3:::bucket-{*}-policy` corrupts the depth count. The branches diverge subtly: `iam_policy_analysis` (652-665) walks braces; `iam_json_policy_analysis` (807-824) walks parens because it expects `jsonencode(…)`; `helm_set_value` (747-773) walks braces but doesn't re-parse like the JSON variant. None check escape sequences. |
| 11 | `scripts/_attack_graph.py:801` (Mermaid edge labels) | **Mermaid edge label not escaped — pipe/quote breaks Mermaid syntax** | `{fid} {arrow}\|"{lbl}"\| {tid}` embeds the edge label directly. If an edge label contains `\|` or `"`, Mermaid syntax breaks. Today's edge labels come from the catalogue's hand-written regex captures (`"role"`, `"iam_profile"`, `"kms_key"`), so the risk is dormant — but a future capture grabbing a Terraform identifier (e.g., a data-source name) exposes it. |
| 12 | `scripts/_threat_intel.py:280` | **`entry_map` no fallback when a finding's ID isn't in the catalogue** | `entry_map = {e["id"]: e for e in entries}` then `entry_map.get(f["id"], {})` returns `{}`. A finding from a misconfigured detector (or a synthetic finding like `SYN-SCAN-FAILED` from R30.10) silently gets empty `cwes`, no KEV promotion, no EPSS ranking. Add a stderr warning when a finding's id is missing — surfaces detector/catalogue drift. |
| 13 | `scripts/gen_rule_docs.py:114` | **Regex pattern not escaped for markdown code-fence** | `f" matching `/{regex}/`"` splices the regex into a backtick-delimited code span. A regex containing a literal backtick or certain escape sequences breaks the fence and leaks raw HTML into the generated docs page. No rule in today's catalogue exercises this, but a contributor authoring a rule with `pattern: '...`...'` (literal backtick) breaks the doc render. Wrap with `re.escape` for the markdown layer or use a different fence style (`<code>`). |
| 14 | `scripts/_attack_graph.py:614` | **Force-layout physics runs 400 ticks unconditionally** | The embedded JS at line 614 always iterates 400 times regardless of node count. A 10k-node graph spends 10+ seconds in the nested O(n²) repulsion loop at lines 640-646. The standalone HTML render becomes unusable on monorepos. Adaptive tick count: `Math.min(400, 100 + 10 * nodes.length)`. |
| 15 | `scripts/_attack_graph.py:359` | **Magic threshold `60` for graph pruning — no docstring rationale** | Pruning triggers when `len(node_list) > 60`. No explanation: is 60 a Mermaid rendering limit or a human-readability heuristic? A 65-node graph gets pruned; a 200-node graph cliffs into different behaviour. Add a one-line comment explaining the source of the constant. |

---

## Brittleness — works today, breaks under stress

| # | File:line | Brittleness | Trigger |
|---|---|---|---|
| 16 | `scripts/_threat_intel.py:194, 232` | **EPSS / KEV cache JSON parsing unguarded** | `json.loads(cache_path.read_text())` has no try/except. A corrupted cache file or a future EPSS schema change raises `JSONDecodeError` that's NOT caught. Callers see "no KEV/EPSS enrichment" instead of a loud error message. Wrap with try/except + a stderr log + fall back to empty cache. |
| 17 | `scripts/_mitre.py:41` | **MITRE_ATTACK_VERSION pinned without runtime drift check** | The module documents that `check_attack_drift.py` verifies techniques exist at the pinned version, but there's no import-time guard. If the catalogue was re-mapped against ATT&CK v18 without updating this constant, the mismatch only surfaces when CI runs. Add a `_check_drift()` call at module import (cached) — fail fast on first run. |
| 18 | `scripts/_output.py:1116, 1224, 1544` | **Urgency-rank fallback inconsistent (9, 9, 2)** | Three sites call `URGENCY_RANK.get(u, X)` with three different fallback values: `9`, `9`, `2`. An unknown urgency tier sorts differently in each render path. The R30.10 consolidation introduced the constants but didn't unify the fallback. Pick one (recommend `URGENCY_RANK_ASCENDING["INFO"]` = 4) and apply everywhere. |
| 19 | `scripts/_output.py:444, 448` (SARIF emit) | **Resource names + paths injected into SARIF JSON without normalization** | `f"Finding {f['id']} on {f['resource'] or 'file'}"` at line 444 and the artifact `uri: f["file"]` at line 448 trust the engine output. A resource name with a newline breaks SARIF JSON structure (the message field is a literal string but `json.dumps` only escapes within a string, not across one). A Windows file path with backslashes isn't URI-normalized. SARIF consumers parsing the URI may fail. |
| 20 | `scripts/detect.py:1527` (`cross_module`) | **No check that resolved `child_dir` is a directory** | The path resolution succeeds even on a deleted directory, a regular file, or a broken symlink. The subsequent file-listing silently iterates zero entries and the rule reports "no findings" — indistinguishable from "no sensitive variable in child module". |
| 21 | `scripts/_hcl.py:204-205` | **Char-by-char rewrite of block comments is O(n) per comment** | The R30.10 fix uses `"".join(c if c == "\n" else " " for c in m.group(0))`. Correct but slow on a 10MB comment-heavy file. `re.sub(r'[^\n]', ' ', m.group(0))` is ~10× faster. Cosmetic; flagged for completeness. |

---

## Subagent claims rejected on re-read

Three subagent findings demoted or rejected:

- **"`_lsp.py:182-187` _check_arity allows `**kwargs`"** — `**kwargs` only collects keyword arguments; positional calls work fine. A wrapper with `**kwargs` does NOT break `scanner(path, entries)` positional invocation. The `*args` rejection is the correct boundary. Re-read confirms no bug.
- **"`detect.py:505-510` coordinate-space mismatch on `hcl_context` block attribution"** — the R30.10 fix to `_hcl.strip_hcl_context` (preserving newlines inside block comments AND length) means `m.start()` is genuinely the same offset in both the stripped text and the original. The comment at lines 481-487 documents this. The agent's analysis predated the R30.10 fix.
- **"`check_terragoat_snapshot.py:46-51` empty stdout caught after json.loads"** — subagent self-rejected; the order is correct (empty-stdout check happens before json.loads).

---

## Recommended fix order

Ranked by **(severity × user impact) ÷ effort**:

1. **HTML escape every engine-supplied field in `_output.py`** — 6+ injection sites (lines 444, 763-770, 1566, 1605-1607). Wrap with `html.escape()` or use `Markup`-style escaping. (Closes #1, #2; partial: also closes some of #19.)
2. **HTML escape in `_attack_graph.py:797-810` standalone HTML sidebar** — same shape as R30.8's TypeScript fix; this is the missed Python equivalent. (Closes #3.)
3. **Fix `SYN-SCAN-FAILED` `section` to a valid value** — change `"engine"` to `"security"` or `"verification"`. (Closes #8.)
4. **Add `try: except OSError, ValueError:` around `(caller_dir / src).resolve()` in `cross_module`** — matches the `module_unused` shape. (Closes #6.)
5. **Apply R30.10's quote-aware comment strip to `_extract_var_defaults_by_dir` module-flow path** — 50 lines below the locals branch that already has it. (Closes #7.)
6. **`_mermaid_id` collision fix** — use a hash suffix when the sanitized form collides, or use base64-like encoding. (Closes #4.)
7. **Deduplicate `INTERNET → sg → resource` edges** — track `(from, to)` seen-set before append. (Closes #5.)
8. **`_threat_intel.py` cache + entry_map fallbacks** — wrap cache JSON parse in try/except; warn on missing entry. (Closes #12, #16.)
9. **`gen_rule_docs.py` regex backtick escape** — defensive but low-frequency. (Closes #13.)
10. **`_output.py` urgency-rank fallback unification** — pick one fallback constant. (Closes #18.)

Items 1-3 are the security-critical XSS surface; do these in one PR. Items 4-7 are correctness bugs with subtle reproducers. Items 8-10 are hardening.

---

## Structural finding

**Three rounds of audits + fixes have closed the major failure surfaces.** Round 4's most material finding is the HTML XSS in `_output.py` and `_attack_graph.py`'s standalone HTML — a class the R30.8 round closed only in the VS Code extension's TypeScript file, missing the Python-emitted HTML report and the standalone attack-graph HTML. The lesson: when fixing a class of bug ("untrusted field injected into HTML"), grep the *whole repo* for the pattern, not just the file the audit cited. The audit pointed at `attackGraph.ts`; the fix should have pulled `_output.py` and `_attack_graph.py` into the same PR.

The two deferred structural items (`_brace_walk` helper and `_output.py` CSS dedup) remain the highest-leverage *next* moves. Both are dedicated-PR scope; both would close 5+ remaining findings at once (the 12 brace-walking duplications in `detect_in_file`; the 2 urgency-colour duplications + the inline CSS-in-f-strings problem in `_output.py`).

`_threat_intel.py` + `_mitre.py` audited cleaner than expected. The biggest residual risk is `detect_in_file`'s 12 detector branches — each has its own coordinate-handling, brace-walking, and var-resolution behaviour, and the prior audits have shown that any "fix" to one branch needs to be propagated to all 12. That's exactly what `_brace_walk` extraction prevents.

---

## Counts

- Subagent reports returned ~40 raw findings.
- Synthesised to **21 findings** + 3 rejected on re-read.
- **8 critical, 7 high-severity smells, 6 brittleness** items.
- 1 finding (#8) is a regression introduced by R30.10 — same pattern that round-3 audit found in R30.9. **Pattern: introduce code that *uses* a constrained vocabulary (here, `_VALID_SECTIONS`) without grepping the validator.**
