# HCL parser migration — make python-hcl2 required and primary

> **STATUS: COMPLETE once Step 5 merges (r2).** Steps 0–4 done (#36, #37,
> #38, #40 — the re-land of #39 —, #41); Step 5 in review. The per-handler
> tree migration originally listed for Step 5 is closed as not needed
> (§14 item 27). Revision 2 follows an
> independent review of r1; every factual claim in r2 was checked against the
> code on 2026-10-25. Supersedes the "Scope B is a separate ~1–2 week
> initiative" note in `tasks/policy-dsl-draft.md` §10 and builds on the
> Scope-A seam in its §6. Closes `tasks/TODO.md:327` (`block_has_arg` depth).
>
> Each PR implementing this spec says "implements §N" and ticks the matching
> box in §12.

## 1. Problem

Detection runs on a regex + brace-counting view of each file. `python-hcl2` is
optional, absent from `pyproject.toml`, and used in exactly one place
(`_hcl2_block_arg_value`, for heredoc attribute values). Probing the engine
with small hand-written corpora (2026-10-25; exact fixture text in Appendix A)
gave:

| # | Corpus | Expected | Actual | Cause |
|---|---|---|---|---|
| P1 | SG with ingress `10.0.0.0/8`, egress `0.0.0.0/0` | clean | `SEC-AWS-SG-001` HIGH | rule is a file-wide `grep`; no ingress/egress distinction |
| P2 | SG ingress port 22, `cidr_blocks = var.open`, `default = ["0.0.0.0/0"]` | `SEC-AWS-SG-001` | nothing | `grep` kind never resolves variables |
| P3 | `aws_vpc_security_group_ingress_rule`, `cidr_ipv4 = "0.0.0.0/0"`, port 22 | finding | nothing | no rule covers the resource |
| P4 | heredoc `description` containing the text `cidr_blocks = ["0.0.0.0/0"]` | clean | `SEC-AWS-SG-001` HIGH | `grep` sees string contents as code (with or without hcl2) |
| P5 | log group, no `retention_in_days`, multi-line `tags` map with a `retention_in_days` key | `COST-AWS-RISK-001` | nothing | `block_has_arg` matches at any depth, including map keys |
| P6 | SG ingress port 22 from `0.0.0.0/0` | CRITICAL (per `escalation:`) | HIGH | `escalation:` is never read by the engine |

Related problems found while reviewing:

- CI never installs `python-hcl2`, so CI tests only the regex path.
- `integrations/mcp-server/Dockerfile:11` and `integrations/run-task/Dockerfile:8`
  copy only `scripts/detect.py`, not its sibling `_*.py` modules, so the
  engine cannot import in those images. Only the root `Dockerfile` image works
  (and `docker.yml` builds only that one). Fixed in §6 (Step 0).
- `find_blocks` reports some resources one line early: its `^\s*` header
  regex (MULTILINE) also consumes a preceding blank line. In a file whose
  second resource starts on line 5, the engine reports line 4. This is a
  user-facing bug, but **out of scope here** (§4.5); it needs its own change
  with a baseline-migration note, because line numbers are part of baseline
  keys (`_baseline.py:168`).

## 2. Goals / non-goals

**Goals**
- `python-hcl2` is always available on every surface, from one vendored copy
  at one version.
- Each `.tf` file is parsed once per run. Handlers read a structured resource
  model, not raw body text.
- Attribute lookups are top-level by default; nested lookups are explicit.
- Probes P1–P6 become fixtures and give the expected result.
- No silent loss of coverage: a file the parser rejects is still scanned by
  every rule kind, and the rejection is reported.
- No finding changes its `file`, `line` or `resource` because of this
  migration (§4.5).

**Non-goals**
- `_apply_fixes.py` stays text-based.
- Fixing the `find_blocks` line off-by-one (§1).
- IAM JSON policy analysis (`iam_policy_analysis`, `iam_json_policy_analysis`)
  keeps its `_hcl_object_to_json` path. Revisit after §4.1: hcl2 4.3.5 renders
  `jsonencode(...)` as a Python repr, but 6.x/7.x render it as JSON, which may
  make migration easy.
- Parsing `.tfvars` / `.tfvars.json` or workflow YAML. These keep their
  current text handling. `.tf.json` is not scanned today and stays out of scope.
- No new rule families. Rule rewrites in §9 are limited to the existing
  catalogue.
- `kind: grep` survives for non-HCL inputs (workflow YAML, secret scanning).

## 3. Reversal of the stdlib-only principle

This spec drops the "stdlib-only core" promise. The dependency is two
pure-Python, MIT-licensed packages (`python-hcl2`, `lark`), vendored (§4.2),
so no surface requires a `pip install`.

Docs to update in Step 1 (lines as of 2026-10-25):
`CONTRIBUTING.md:168`; `README.md:63`, `158`, `268`, `288`;
`SKILL.md:48`, `260`–`286` (the `--no-hcl2` / `--use-hcl2` section), `1908`;
`docs/cli.md:112`–`114`, `246`–`248`; `docs/policy-dsl.md:117`;
`docs/terraform-provider.md:13`, `189`; `docs/vscode-extension.md:53`;
`vscode-extension/README.md:107`, `175`; `Dockerfile:12`–`15` (comment and
`pip install`); `vscode-extension/scripts/bundle-engine.js:137`, `190`
("stdlib-only by contract" comments).

## 4. Decisions

### 4.1 Parser version

Selection criteria, in order:

1. **Pure Python, including everything it imports.** 8.x declares a
   dependency on `regex` (a compiled C extension); 7.3.0 imports `regex` in
   `hcl2/reconstructor.py` without declaring it. Neither can be vendored.
2. **`with_meta=True` yields `__start_line__` / `__end_line__`** on blocks.
   (Reported by review: 8.x accepts the option but emits no line keys.)
3. **Parses all 674 `.tf` files in the repo.**

**Decision: pin 7.2.1**, subject to a Step-1 check that it meets criteria 2–3
and a diff of its output shape against 4.3.5 on the full corpus (strings,
heredocs, `jsonencode`, list rendering). If 7.2.1 fails any criterion, pin
4.3.5 (already known to meet all three). Re-check the MIT licence for the
pinned version.

**Step-1 check result (2026-10-25): 7.2.1 pinned, with lark 1.3.1.** It
imports only the stdlib and lark; parses all 676 `.tf` files (two were added
since r2); emits the same 1,887 `__start_line__` keys as 4.3.5. Its output
differs from 4.3.5 in 91 values, all improvements: `jsonencode(...)` and
other nested expressions use JSON-style double quotes (66 + 18), `\"`
escapes are unescaped (7), and `type = string` gives `string` rather than
`${string}`. Both licences are MIT.

### 4.2 Distribution: one vendored copy everywhere

- `scripts/_vendor/` holds `hcl2/` and `lark/` (all `.py` files **and** all
  `.lark` grammar files — `hcl2/hcl2.lark` is required at import) plus
  upstream `LICENSE` files.
- It is produced only by `scripts/vendor_deps.py` (downloads the pinned
  wheels, extracts the needed files, records versions and hashes in
  `scripts/_vendor/VERSIONS`). Never edited by hand.
- `_hcl.py` (not `detect.py`) inserts the vendored directory at the front of
  `sys.path` before importing `hcl2`. Other entry points (`tests/`,
  `scripts/self_test.py`, `scripts/gen_rule_docs.py`) import `_hcl` without
  `detect`, so `_hcl.py` is the only place that is always imported first.
  Locating the directory mirrors `detect._default_catalog_dir()`: next to
  `_hcl.py` in the source layout; via a `tf_analyze_vendor` package-data
  package in the installed layout.
- **The vendored copy always wins** over any installed `hcl2`. This makes
  every surface run the same parser and avoids clashes with other packages
  that also provide a module named `hcl2`. Therefore `pyproject.toml` does
  **not** declare `python-hcl2` as a dependency; the wheel ships the vendored
  copy instead.
- The Dockerfiles drop their `pip install python-hcl2==4.3.5` and copy
  `scripts/_vendor/` with the engine. That is four images, not three:
  `demo/Dockerfile` (the public scanner) also bundles the engine, and never
  installed `python-hcl2`.
- `bundle-engine.js` bundles `scripts/_vendor/`, and its smoke test asserts
  that `import hcl2` resolves to the bundled copy.

**Grammar cache.** lark caches the built parser as a file next to
`hcl2/parser.py`. Without it, import takes ~0.35–0.40s instead of ~0.05s —
longer than a whole scan of `examples/terragoat` (~0.3s). So:

- `vendor_deps.py` pre-builds the cache; the `.vsix`, the wheel and the
  Docker images ship it.
- In a git checkout the cache file is gitignored and built on first run.
- If the vendored directory is read-only and the cache is missing, fall back
  to a cache path under the user cache dir (`$XDG_CACHE_HOME` /
  `~/Library/Caches`), and if that fails, rebuild in memory. Step 1 must
  confirm how to redirect the cache path for the pinned version.

### 4.3 One parse pass (`FileModel`)

> **As built in Step 2:** instead of a `FileModel` map threaded through
> every consumer, `_hcl.parse_tf(text)` is memoised on the file text
> (LRU, 1,024 entries). The effect is the same — each distinct `.tf` text
> is parsed once per process and every caller shares the tree — with no
> signature changes, and long-lived callers (LSP, trend, fleet) re-parse
> only text that actually changed, which replaces the mtime cache below.
> Consumers that still scan text (var defaults, provider constraints,
> module sources, …) don't parse, so the one-parse property holds; they
> move onto the tree in Steps 3–5. The joining rules below (`(type,
> name)`, ambiguous → `attrs = None`), BOM stripping, `.tf`-only parsing
> and the LSP Information diagnostic are implemented as written.
> `_build_resource_index` is memoised on the last corpus, so it is built
> once per scan.

Built once, in `main`'s pass-1 read loop (`detect.py` ~2997–3005, where
`all_text` is filled), for `*.tf` files only:

```python
FileModel = {
    "path": Path,
    "text": str,                 # raw normalised text, as passed to detect_in_file today
    "tree": dict | None,         # hcl2.loads(text_without_bom, with_meta=True); None on failure
    "parse_error": str | None,
}
```

The map `{path: FileModel}` is passed to every consumer that re-reads or
re-scans `.tf` text today: `_run_detection` → `detect_in_file`,
`detect_corpus`, `_extract_var_defaults_by_dir`, `_build_resource_index`
(built **once**; today it is built at `detect.py:728` and again at
`detect.py:3121`), `_build_sensitive_var_index`,
`_extract_provider_constraints`, module-source scanning, and the trend and
fleet modes. Consumers not migrated yet keep reading `text`.

- **Parse input.** Raw normalised text with a leading UTF-8 BOM removed
  (`_read_normalized` does not strip it today). Not comment-stripped text:
  `strip_hcl_context` is not heredoc-aware (it blanks `#!/bin/bash` inside a
  heredoc, and a stray `"` inside a heredoc stops a later real comment being
  stripped).
- **Joining tree to regex blocks.** `detect_in_file` still produces resource
  blocks with `find_blocks` (they supply `start_line`, `body`, and positions
  for `_apply_fixes`). Each block gets `attrs` = the tree's subtree for the
  same `(type, name)` in the same file. Terraform rejects duplicate
  `(type, name)` in a module, so in valid code the join is unique. If the
  tree has no match, or more than one regex block has the same key (e.g.
  `resource "..." "..." {` text inside a heredoc), that block gets
  `attrs = None` and uses the fallback (§4.7).
- **Non-`.tf` inputs** (`extra_text`: workflow YAML, `.tfvars`,
  `.tfvars.json` — `detect.py:1996`) are never parsed and never reported as
  parse failures.
- **LSP** (`_scanner` in `detect.py:1638`): cache `FileModel`s per path,
  keyed on file mtime and size, so a `didChange` re-parses only the changed
  file. A parse failure is sent as one `Information` diagnostic on line 1.

### 4.4 Lookup semantics

How hcl2 represents a resource body (verified against 4.3.5; re-verify on
the §4.1 version):

- **Nested block** (`ingress { ... }`) → a list of dicts, each with
  `__start_line__` / `__end_line__`. Repeated blocks are list entries.
- **List-of-objects attribute** (`ingress = [{ ... }]`, valid for
  `aws_security_group`) → a list of dicts **without** line metadata.
- **Object attribute** (`tags = { ... }`) → a plain dict, no line metadata.
- **`dynamic "X" { content { ... } }`** → under the key `dynamic`, as
  `[{"X": {"for_each": ..., "content": [{...}]}}]`.
- **Expressions** → strings wrapped in `${...}`.
- **Heredocs** → plain strings (4.3.5: markers removed; tab-indented `<<-`
  bodies are not dedented and the trailing newline is dropped).

Rules:

1. `block_has_arg(attrs, "x")` is true only for a key of the resource itself.
   Never inside object attributes or nested blocks.
2. `nested_path` (`a.b.c`) walks nested blocks **and** list-of-objects
   attributes the same way, so `ingress { }` and `ingress = [{ }]` behave the
   same. A plain object attribute is walked only if the path explicitly names
   it.
3. **Presence (`resource_missing_arg`).** When a segment is repeated, the
   path counts as present only if **every** instance satisfies the rest of
   the path. So the rule fires if *any* instance lacks the setting. A rule
   can opt out with `instances: any`.
4. **Value matching (`resource_arg`, `hcl_attr`).** Fires if **any**
   instance's value matches.
5. `resource_arg` gains `nested_path` support. Today it ignores the key and
   relies on `block_arg_value` matching at any depth; `SEC-AWS-MSK-001`
   already sets `nested_path` on a `resource_arg` pattern and is the test
   case (`test_positive_fixture[aws_msk_plaintext]`).
6. `dynamic "X"` content is normalised to a plain `X` block during model
   construction, replacing `_expand_dynamic_blocks` on the tree path. Values
   from `for_each` (`${X.value}`) are unknown and never match a value regex.

### 4.5 Line numbers

`finding.line` always comes from `find_blocks` `start_line`, exactly as
today. hcl2's `__start_line__` is never used for a finding's line. Reason:
`_apply_fixes` only patches when `finding.line` leads to the resource's
opening line (`_apply_fixes.py:268–278`); baseline keys include `line`
(`_baseline.py:168`); inline suppressions and de-duplication also key on
it; and hcl2's line differs from `find_blocks`' (the off-by-one in §1).

### 4.6 Values and variables

- **One rendering function**, `render_hcl(value) -> str`, used wherever a
  tree value is compared to a catalogue regex: bools as `true`/`false`,
  `null`, numbers unchanged, strings unquoted (matching what
  `block_arg_value` returns today), lists and objects in HCL form with
  double-quoted strings (`["0.0.0.0/0"]`, not `['0.0.0.0/0']`).
  **Definition by test:** for every `resource_arg` / `hcl_attr` pattern and
  every fixture, `render_hcl(tree value)` must equal today's
  `block_arg_value(body, arg)` result, except for listed, justified cases
  (heredocs, multi-line values that `block_arg_value` truncated today).
- **Typed variable values** go in a **separate** map (`var_values`), built
  from the tree. `var_defaults` stays a `str → str` map, because it also
  carries locals, module inputs and `__aws_default_tags__`, and
  `_resolve_var_ref` calls `.strip()` on its values (`detect.py:310`, `327`).
- **Interpolation unwrap.** A value is a single reference only if it is
  exactly one `${...}` whose braces balance and close at the end of the
  string, not preceded by `$` (`$${x}` is an escape). `"${var.a}-${var.b}"`
  and `${{for ...}}` are not single references and stay unresolved.
- **Plan / state mode** (`_plan_state.py:67–200`) already evaluates
  `resource_arg`, `resource_missing_arg` and `hcl_attr` over structured JSON,
  with first-instance semantics and `str(val)` (so `True`, not `true`). It
  must share `render_hcl`, the path walker and the instance rules from §4.4,
  so static and plan results agree.

### 4.7 Fallback when a file cannot be parsed

- Every migrated rule kind defines how it behaves when `attrs is None`, using
  regex helpers that apply the **same semantics** as §4.4 as far as text
  allows: a depth-0 `block_has_arg` (via `brace_walk`), every-instance
  presence, `nested_path` support in `resource_arg`.
- Structured rewrites in §9 (e.g. `SEC-AWS-SG-001`) keep a regex fallback.
  Known gaps (e.g. variable resolution of list defaults) are listed in the
  rule's YAML under `fallback_limitations:`.
- The regex helpers are **kept permanently** as the fallback. Only their
  any-depth / any-instance behaviour is removed.
- **Test:** CI runs the fixture suite a second time with a test-only switch
  (`TF_ANALYZE_TEST_FORCE_FALLBACK=1`) that sets every `tree` to `None`.
  Every positive fixture must still fire, except those listed under
  `fallback_limitations:`.

### 4.8 Reporting parse failures

A parse failure is a tool diagnostic, **not a finding**: it is not in
`findings`, does not affect the score, is not a SARIF result (so it never
becomes a GitHub code-scanning alert), and never fails the run. Only `.tf`
files can produce one (§4.3).

- stderr: one `WARN: <file>: parse failed, scanned in fallback mode: <reason>`
  line per file.
- JSON: `summary.parse_fallback_files: [{"file": ..., "reason": ...}]`,
  present only when non-empty (so output is unchanged for corpora that
  parse cleanly).
- SARIF: SARIF output has no `invocations` today. Add one
  `runs[].invocations[0]` with `executionSuccessful: true` and one
  `toolExecutionNotifications` entry (level `warning`) per file — again
  only when there is at least one.
- text / HTML / PR summary: one line, `N file(s) scanned in fallback mode`,
  only when N > 0.
- LSP: see §4.3.
- No `--strict-parse` flag. Add one only if a user asks to fail CI on
  fallback.

### 4.9 Scan cache

`_cache.corpus_hash` (`_cache.py:23–56`) covers only file text and catalogue
entries. A warm `.tf-analyze-cache.json` would return old-engine results
after any step that changes handlers without touching the catalogue. In
Step 1: bump the cache format version; add the engine version and the
vendored parser version to the hash; store `parse_fallback_files` in the
cache entry so it survives a cache hit.

### 4.10 `escalation:`

8 catalogue entries carry `escalation:`. 3 conditions are mechanical
(`SEC-AWS-SG-001` port 22/3389, `STK-AZURE-NSG-001` port 22/3389,
`SEC-GCP-IAM-001` `allUsers`/`allAuthenticatedUsers`). The other 5 are
environment or cost judgements (`is_production_environment`,
`estimated_monthly_cost_usd > 500`, `resource_holds_production_data`) that
the skill's judgement pass reads (`SKILL.md:133`, `1007`, `1039`); the engine
cannot evaluate them.

Decision:
- An escalation entry with a structured `match:` (e.g.
  `match: {ports: [22, 3389]}`) is evaluated by the engine. Convert the 3
  mechanical conditions to this form.
- An entry with only a free-text `condition:` is judgement-pass metadata,
  documented as such in `docs/` and `SKILL.md`. The engine ignores it.
- `_catalog.validate_catalog_entry` accepts both forms and rejects an entry
  with neither.

## 5. Verification (applies to every step)

Each PR includes:

1. **Suite green**, in CI with the vendored parser.
2. **Probe fixtures.** P1–P6 live in `fixtures/` as `parser_probe_p1` …
   `parser_probe_p6`, with the exact text from Appendix A. They start as
   `xfail(strict=True)` and flip to passing in the step that fixes them, so a
   probe that passes early fails the build.
3. **Corpus diff on `examples/` and `fixtures/`.** Run `--format json` before
   and after; paste added/removed findings (rule ID, file, resource) into the
   PR description. Every change needs a one-line justification. (`fixtures/`
   matters: the depth-0 trial changed nothing in `examples/` but one result
   in `fixtures/`.)
4. **Fallback run** (§4.7) green from Step 2 onward.
5. **Performance.** `tests/test_perf.py` budget unchanged; a warm
   `examples/terragoat` scan is no more than 1.2× today's time. A cold start
   (no grammar cache) is recorded but has no ratio limit: building the
   grammar takes ~0.45s, longer than the whole scan (~0.27s), so no cold
   run can meet a ratio against today. It happens once per fresh checkout
   or pip install; the Docker images and `.vsix` ship the cache pre-built.
   *(Amended in Step 1; r2 had a 1.5× cold-start limit. Step 1 measured:
   warm 1.11×, cold 2.70×.)*

## 6. Step 0 — fix the MCP and Run Task images (est. ½ day, independent)

Separate PR; can ship before anything else.

- `integrations/mcp-server/Dockerfile` and `integrations/run-task/Dockerfile`
  copy all of `scripts/*.py` (later also `scripts/_vendor/`), not only
  `detect.py`.
- Add both images to `docker.yml` or to a CI smoke job that runs
  `detect.py --list-rules` inside each image.

## 7. Step 1 — vendored parser, always on (est. 2–3 days)

- Run the §4.1 check; pin the version; write `scripts/vendor_deps.py`;
  commit `scripts/_vendor/` (gitignore the grammar cache).
- `_hcl.py`: vendored-path insert (§4.2); grammar-cache handling (§4.2);
  remove `_USE_HCL2`, `_HAS_HCL2`, `_enable_hcl2_or_warn`,
  `_enable_hcl2_default`.
- `--use-hcl2`, `--no-hcl2`, `TF_ANALYZE_USE_HCL2`, `TF_ANALYZE_NO_HCL2`
  become no-ops that print a one-line deprecation notice to stderr; removed
  in the following minor release; noted in `CHANGELOG.md`. They are not
  removed outright because `action.yml` defaults to the `:latest` image, so
  users would get a broken pipeline with no change on their side.
- Remove every in-repo use of those switches (as of 2026-10-25):
  `integrations/run-task/server.py:171`, `integrations/run-task/Dockerfile:13`,
  `scripts/gen_sample_reports.py:50`, `scripts/gen-cli-docs.py:83`, and the
  tests in `test_apply_fixes.py`, `test_cache.py`,
  `test_compliance_owasp_iac.py`, `test_lsp_server.py`,
  `test_main_mode_dispatch.py`, `test_policy_dsl.py`, `test_pr_summary.py`,
  `test_render_report_characterization.py`, `test_rule_docs.py`.
- Remove the "python-hcl2 not installed" stderr note.
- Dockerfiles: drop `pip install python-hcl2`.
- `bundle-engine.js`: bundle `_vendor/` and the pre-built cache; smoke test
  asserts the bundled `hcl2` is the one imported.
- `pyproject.toml`: ship `_vendor` via a `tf_analyze_vendor` package-data
  package (§4.2).
- Cache changes (§4.9).
- Docs (§3).
- Add probe fixtures P1–P6 as `xfail(strict=True)`.

**Done when:** suite green in CI; `.vsix` smoke test passes on a clean
Python with no site-packages; a fresh-venv `pip install .` scans with the
vendored parser; the Docker images scan with it; §5.5 cold and warm timings
recorded.

## 8. Step 2 — one parse pass, fallback, `block_has_arg` (est. 1½–2 weeks)

- Build `FileModel`s in pass 1 and pass the map to every consumer in §4.3,
  including trend, fleet and LSP (mtime cache).
- Build `_build_resource_index` once.
- Join tree subtrees to `find_blocks` blocks (§4.3).
- Parse-failure reporting in all formats (§4.8).
- `block_has_arg` and `block_has_nested_path` on `attrs` with §4.4
  semantics (rules 1–3); regex fallbacks with the same semantics (§4.7).
- Add `nested_path` to `STK-GCP-CLOUDSQL-IAMAUTH-001` and
  `STK-K8S-INGRESS-001` (the only two tests out of 1,124 that failed in a
  depth-0 trial on 2026-10-25).
- Fixtures: a resource with one complete and one incomplete instance of the
  same block (expected to fire); `ingress = [{...}]` attribute form; a file
  with a BOM; a file that fails to parse (expected: findings from fallback,
  plus a diagnostic).
- Fallback CI run (§4.7).
- Close `tasks/TODO.md:327`.

**Done when:** P5 passes; the new fixtures pass on both the tree and fallback
paths; corpus diffs reviewed.

## 9. Step 3 — values, the other main kinds, plan mode (est. ~2 weeks)

> **As built:** `render_hcl`, `single_interpolation`, `attrs_values_at` /
> `resource_values_at` (tree) and `block_values_at` (fallback);
> `resource_arg` and `hcl_attr` moved onto them; `resource_body_contains`
> masks comments and heredocs; plan / state mode shares the renderer, the
> path walk and the instance rules. Two items moved to Step 4 — see §14
> items 13–14 (typed `var_values`, and converting `resource_body_contains`
> uses).

| Kind | Uses | Change |
|---|---:|---|
| `resource_arg` | 86 | `render_hcl` values; `var_values` resolution; any-instance matching; `nested_path` support (§4.4.5) |
| `hcl_attr` | 25 | read from `attrs` via `render_hcl` |
| `resource_body_contains` | 63 | review each use; most become `resource_arg` or `nested_path`. The kind remains as a text escape hatch, but now searches the body with string and heredoc contents masked |
| `resource_missing_arg` | 222 | already done in Step 2 |

- `render_hcl` and its golden test (§4.6).
- `var_values` and the interpolation-unwrap rule (§4.6).
- A heredoc-aware masker for `resource_body_contains`. It needs a small
  tokenizer (strings, escapes, `${}` nesting, `<<`/`<<-` heredocs) — not
  `strip_hcl_context`, which is not heredoc-aware.
- Align `_plan_state.py` with `render_hcl` and the §4.4 instance rules.

**Done when:** the `render_hcl` golden test passes; `aws_msk_plaintext`
fires via `nested_path`; static and plan mode agree on a shared fixture set;
corpus diffs reviewed.

## 10. Step 4 — `grep` rules on `.tf`, and `escalation:` (est. ~1 week)

> **As built:** `scripts/_network.py` reduces six firewall / security-group
> resource types to one inbound-rule model (tree and text views, `var.X` /
> `local.X` resolution); `firewall_open_port` uses it; `SEC-AWS-SG-001` and
> `STK-AZURE-NSG-001` are rewritten onto it; structured `escalation:
> match:` is evaluated in `detect_in_file` and validated in `_catalog`;
> every remaining `grep` pattern carries a `text_scan:` reason (enforced
> by a test). All six probes pass. See §14 items 17–21.

30 catalogue entries use `kind: grep` (49 patterns). The CRITICAL/HIGH ones,
in priority order, network first:

`SEC-AWS-SG-001`, `STK-AZURE-NSG-001`, `SEC-AWS-IAM-001`, `SEC-AWS-IAM-002`,
`SEC-AWS-IAM-OIDC-001`, `SEC-AWS-ECS-001`, `SEC-AWS-ECS-002`,
`SEC-USERDATA-001`, `SEC-PROVISIONER-001`, `SEC-PROVISIONER-002`,
`SEC-DATASOURCE-003`, `SEC-SECRETS-001`, `MOD-PIN-001`, `MOD-SUPPLY-001`,
`MOD-SUPPLY-003`, `ROB-DRIFT-001`, `STK-K8S-IMAGE-SIGNED-001`,
`SEC-CICD-001`, `SEC-CICD-002`, `SEC-CICD-003`.

For each: if it inspects HCL resources, rewrite it as a structured kind with
a fallback (§4.7); if it scans non-HCL text (CI workflows, secrets), keep
`grep` and say why in the YAML.

`SEC-AWS-SG-001` and `STK-AZURE-NSG-001`: generalise the existing port-aware
`firewall_open_port` kind (`_handlers_security.py:293`, used by 3 GCP rules,
already handles port ranges) rather than adding a new kind. For AWS cover:
`ingress` blocks and the `ingress = [{...}]` attribute form on
`aws_security_group`; `aws_security_group_rule` with `type = "ingress"`;
`aws_vpc_security_group_ingress_rule`; IPv4 and IPv6 (`cidr_blocks`,
`ipv6_cidr_blocks`, `cidr_ipv4`, `cidr_ipv6`), after variable resolution.

`escalation:` per §4.10.

**Done when:** P1–P4 and P6 pass (P6 expects CRITICAL via the structured
`match:`); corpus diffs reviewed.

## 11. Step 5 — remaining handlers and call sites (est. 2–3 weeks, incremental)

> **Increment 5a (as built):** instead of moving the 34 `block_arg_value`
> call sites one by one, `block_arg_value` itself became top-level only —
> after an instrumented run over all 637 fixture / example directories
> (with and without `--attack-graph`) found exactly one call site whose
> answer changed. That one was a bug: `_resource_is_count_zero` read a
> Cloud Armor `rate_limit_threshold { count = 100 }` as the resource's
> `count` (a nested `count = 0` would have skipped the whole resource for
> every rule). Also fixed: the heredoc path returned only the first
> element of a list value (`val[0]`, a leftover from old python-hcl2), so
> in any body containing a heredoc e.g. `actions = ["s3:GetObject", "*"]`
> lost its wildcard — live for every user since Step 1 made the parser
> always on. A test checks `block_arg_value` against the tree for all
> 2,963 literal top-level settings in the corpus. See §14 items 23–24.
>
> **Increment 5b:** the 19 structural `grep` patterns that still matched
> commented-out code now set `hcl_context: true`, and four file-scope
> patterns that began `^\s*` (`ROB-DRIFT-001/002`, `MOD-SUPPLY-004`,
> `SEC-DATASOURCE-003`) now begin `^[ \t]*` — with comments blanked,
> `\s*` could reach back across blank lines, which cost
> `SEC-DATASOURCE-003` its resource attribution, and even before it
> reported the blank line above the `data` block. README: the
> MITRE / CWE / D3FEND badge was stale (69/53/40% vs 80/68/47%) and is
> now drift-tested; the test-count badge (1,153, wrong) was removed.

- About 54 handlers are registered; about 13 are the generic ones covered
  above, leaving about 40 specialised handlers in `_handlers_*.py`.
- Regex-helper call sites outside the handlers (counts of `find_blocks`,
  `find_simple_blocks`, `block_has_arg`, `block_arg_value`,
  `block_has_nested_path` on 2026-10-25): `detect.py` 24, `_cross_resource.py`
  11, `_policy.py` 4 (the policy DSL's own regex resource view — move it onto
  the tree per `policy-dsl-draft.md` §6), `_registry.py` 4,
  `_attack_graph.py` 1, `_apply_fixes.py` 1 (stays text-based).
- Migrate in order of rule urgency; track in a checklist in this file.
- Remove `_expand_dynamic_blocks` from the tree path once unused there. Keep
  the fallback helpers (§4.7).
- Generate the README rule and test counts from CI output instead of editing
  them by hand.

## 12. Progress

- [x] §6 Step 0 — MCP / Run Task images (#36)
- [x] §7 Step 1 — vendored parser (#37)
- [x] §8 Step 2 — one parse pass, fallback, `block_has_arg` (#38)
- [x] §9 Step 3 — values, main kinds, plan mode (#39, re-landed as #40)
- [x] §10 Step 4 — `grep` rewrites, `escalation:` (#41)
- [ ] §11 Step 5 — `block_arg_value` top-level, text-scan hygiene,
  literal-only `count = 0` (in review)

Estimated total: **7–9 weeks** of one person's time.

## 13. Risks

| Risk | Mitigation |
|---|---|
| hcl2 rejects valid Terraform. Reported for 4.3.5 / 7.2.1: multi-line conditionals with `?` / `:` at the start of a line; a UTF-8 BOM. (Provider-defined functions, `ephemeral` blocks and template directives parse fine.) | strip BOM (§4.3); per-file fallback (§4.7); add a fixture per failing form, re-checked on the pinned version |
| hcl2 heredoc quirks (tab-indented `<<-` not dedented, trailing newline dropped) change values | covered by the `render_hcl` golden test's listed exceptions (§4.6) |
| Grammar-cache misses make cold start slow | pre-built cache in shipped artefacts; user-cache fallback; cold-start budget (§5.5) |
| Vendored `hcl2` shadows another installed `hcl2` in the same process (e.g. a host importing `detect` as a library) | documented; acceptable because the engine needs a known version |
| Results differ between tree and fallback paths | same semantics in both (§4.7); fallback CI run; `fallback_limitations:` lists the known gaps |
| Stale cached results after upgrade | cache version bump and engine/parser versions in the hash (§4.9) |
| Large fixture churn | step-by-step rollout; corpus diffs on `examples/` and `fixtures/` (§5.3) |
| Every-instance presence (§4.4.3) is not exercised by existing fixtures (a trial on 2026-10-25 changed no results) | dedicated repeated-block fixtures in Step 2 |
| Users relying on the removed switches | no-ops with a notice for one minor release (§7) |
| Effort overrun | Steps 0–2 deliver value alone (working images, correct `resource_missing_arg`, parse diagnostics); later steps can be re-planned after Step 2 |

## 14. Decisions log

Resolved 2026-10-25:

1. **Parse failures** — a tool diagnostic, not a finding; no score impact,
   no SARIF result, no run failure, no `--strict-parse` for now (§4.8).
2. **Repeated blocks** — presence requires every instance; value matching
   fires on any instance; `instances: any` opt-out (§4.4).
3. **Deprecated switches** — no-ops with a notice for one minor release (§7).

Added in r2:

4. **Parser version** — 7.2.1 if it passes the §4.1 check, else 4.3.5.
5. **Distribution** — vendored copy always wins; no `pyproject` dependency
   (§4.2).
6. **Line numbers** — unchanged; the off-by-one is a separate fix (§4.5).
7. **`escalation:`** — engine evaluates structured `match:` only; free-text
   conditions stay as judgement-pass metadata (§4.10).

Added in Step 1:

8. **Cold-start budget** — no ratio limit on a cold start; warm-start
   limit stays 1.2× (§5.5). Committing the grammar cache to git was
   rejected: it is a pickle, which can't be reviewed.

Added in Step 2:

9. **Parse once by memo, not by map** — see the note in §4.3.
10. **`instances: any` is needed by exactly one rule today.** Of the 64
    `nested_path` uses, only `SEC-AWS-WAF-002`
    (`rule.statement.rate_based_statement` on `aws_wafv2_web_acl`) passes
    through a block that repeats; one rate-based rule is enough, so it
    sets `instances: any`, pinned by a new `SEC-AWS-WAF-002_clean`
    fixture. Every other path goes through blocks that occur once.
11. **Map attributes are walked when the path names them** (§4.4 rule
    2), on the tree and in the regex fallback. The old regex helper only
    walked blocks, so `nested_path: tags.cost_center` — the worked example
    in `docs/custom-rules.md` — fired on every resource even with the tag
    set. No built-in rule uses a `tags.*` path.
12. **Tree and fallback agree.** A differential test checks both on every
    resource in `fixtures/` and `examples/` for every
    `resource_missing_arg` path that applies (2,180 checks): no
    disagreements, so no rule needs `fallback_limitations:` yet. The
    whole suite also passes with the fallback forced (new CI job).

Added in Step 3:

13. **Typed `var_values` moved to Step 4.** With values rendered back to
    HCL text, the existing string `var_defaults` already resolves every
    `resource_arg` / `hcl_attr` value the catalogue checks (the golden
    and agreement tests pass). The first consumer that needs typed list
    defaults is the `SEC-AWS-SG-001` rewrite (probe P2), so the typed map
    is built there.
14. **`resource_body_contains`: comments and heredocs masked, not
    strings; conversions moved to Step 4.** Masking string contents (as
    r2 said) would break the 43 of the 63 regexes that match quoted
    values such as `"allow-all"`. Comments and heredoc bodies are the
    false-positive source, so those are masked. Converting individual
    uses to `resource_arg` / `nested_path` needs per-rule paths through
    repeatable blocks — the same work as the Step 4 `grep` rewrites — so
    it is done there.
15. **Five `resource_arg` patterns had never fired.** They put a dotted
    path in `arg` (`metadata_options.http_tokens`,
    `versioning_configuration.status`, …), which the old line-based lookup
    could never match: `ROB-AWS-S3-001`, `ROB-AZURE-STORAGE-001`,
    `SEC-AWS-SSRF-001`, `STK-AZURE-FUNCTION-001`, `STK-GCP-FUNCTIONS-001`.
    Dotted `arg` is now walked like `nested_path`. New true positive:
    terragoat `aws_instance.imds_v1_explicit` (`http_tokens =
    "optional"`) now gets `SEC-AWS-SSRF-001`.
16. **Plan mode disagreed with static mode 52 times** on literal-only
    fixture resources (Python `True`/`['a']` rendering, dotted paths,
    `arg` preferred over `nested_path`, first-instance only) — in both
    directions, e.g. `enable_deletion_protection = false` never fired
    `ROB-AWS-ALB-001` in plan mode. Now 0 of 2,041.

Added in Step 4:

17. **Typed variable values come from `var_defaults`.** `_network.parse_literal`
    turns the stored default text (`["0.0.0.0/0"]`) into a list, which
    works identically on the tree and the fallback path — no separate
    tree-built `var_values` map was needed (§14 item 13).
18. **Network findings: one per resource, at the resource line.** The old
    `grep` emitted one finding per matching line — ingress *and* egress —
    at that line. The rewrite emits one per exposed resource at its
    `find_blocks` line, like every other resource kind. This changes the
    baseline key of those findings once (CHANGELOG upgrade note). The
    corpus diff also showed the old rules matching comments: two NSG
    "findings" on comment lines, and a CRITICAL `SEC-GCP-NETWORK-001` on
    an IAP-only firewall because a comment mentioned `0.0.0.0/0`.
19. **`firewall_open_port` semantics, GCP included.** Sources must be in
    `source_ranges` (not anywhere in the body); `direction = "EGRESS"` is
    skipped; an `allow` block without `ports` (or protocol `all`) means
    all ports. Escalation keys accept `urgency:` or the documented
    `new_urgency:`.
20. **`resource_body_contains` is not being converted** (reverses §14 item
    14's deferral). With comments and heredocs masked, the remaining risk
    is low, while converting needs exact per-provider paths (e.g.
    `viewer_protocol_policy` lives in two CloudFront blocks) and a wrong
    path silently loses detection.
21. **`grep` patterns on `.tf` that stay text scans:** secrets
    (`SEC-SECRETS-001`), scripts in strings (`SEC-USERDATA-001`,
    `SEC-PROVISIONER-002`), JSON documents (`SEC-AWS-IAM-001/002`,
    `SEC-AWS-IAM-OIDC-001`, `SEC-AWS-ECS-001/002`) by design; module
    sources, version constraints, `lifecycle`, `data` and `provisioner`
    blocks (`MOD-*`, `ROB-DRIFT-*`, `ROB-VERSION-001`, `SEC-PROVIDER-001`,
    `SEC-DATASOURCE-*`, `SEC-PROVISIONER-001`, `SEC-USERDATA-002`,
    `STK-GCP-DEPRECATION-001`) until structured kinds for non-resource
    blocks exist — candidates for Step 5. The YAML loader keeps flow lists
    as strings and misreads a nested mapping that is an item's first key;
    documented in `catalog/README.md`.
22. **Network rules fail closed.** (From an automated security review of
    the Step 4 commit.) An unresolvable `type` / `direction` / `access`
    (e.g. `type = var.rule_type`) is treated as possibly
    ingress / inbound / allow rather than dropping the rule, and only a
    literal `count = 0` skips a resource — a count from a variable
    default can be overridden by tfvars, and the replaced text scan never
    skipped on count. Other rule kinds still skip a resource whose count
    resolves to 0 through a variable default (`_resource_is_count_zero`,
    pre-existing); reviewing that engine-wide is left open below.

Added in Step 5:

23. **`block_arg_value` is top-level only** (5a, above). Every call site
    — handlers, `_cross_resource`, `_policy`, `_registry`, `detect` — now
    gets the same top-level semantics as the tree, without per-site edits.
24. **Known limitation — hcl2 expression text.** python-hcl2 7.2.1
    stringifies some expressions lossily: string quotes inside a
    function call's list argument are dropped (`toset(["a"])` →
    `toset([a])`), and the text path keeps only the first line of a
    multi-line call (`jsonencode({`). No catalogue regex matches such
    values today (golden and agreement tests pass); a rule that needs to
    should use the IAM / JSON analysers or a `policy` predicate.

25. **`count = 0` skips a resource only when literal** (decided
    2026-10-26). `_resource_is_count_zero` no longer resolves `count`
    through variable defaults: tfvars / `-var` can override a default at
    apply time, so `count = var.enabled ? 1 : 0` with `default = false`
    is now checked by every rule (a literal-condition ternary such as
    `false ? 1 : 0` still skips). Corpus effect: the
    `unguarded_count_ref` fixture's optional Cloud SQL instance gains 8
    findings.
26. **Structural text scans use the HCL-aware lexer** (`code_only: true`;
    from an automated security review of 5b). `hcl_context: true` uses
    the older comment stripper, which is not heredoc-aware and toggles
    on every unescaped quote, so a crafted heredoc could in principle
    confuse its string state and hide code. No practical bypass was
    found (single-line blocks hold one argument), so this is hardening;
    it also stops structure-like text inside heredocs matching. The
    rules that must see heredoc text (`SEC-SECRETS-001`,
    `SEC-AWS-ECS-001/002`) keep `hcl_context`.
27. **Per-handler tree migration closed as not needed.** With
    `block_arg_value`, `block_has_arg` and `block_has_nested_path`
    sharing the tree's top-level, every-instance semantics, and
    `find_blocks` only locating blocks (and supplying line numbers), the
    ~40 specialised handlers already evaluate HCL under the migration's
    rules; moving each onto `attrs` would change no result on the corpus.
    New handlers should still prefer `resource_values_at` /
    `resource_has_path` / `_network` views.

Open:

- Whether and when to fix the `find_blocks` line off-by-one (needs a
  baseline-migration plan).

## Appendix A — probe fixtures

Each is a single `main.tf`.

**P1** — expected: no `SEC-AWS-SG-001`.
```hcl
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

**P2** — expected: `SEC-AWS-SG-001` (CRITICAL after Step 4).
```hcl
variable "open" {
  default = ["0.0.0.0/0"]
}
resource "aws_security_group" "sg" {
  name = "sg"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = var.open
  }
}
```

**P3** — expected: `SEC-AWS-SG-001` (CRITICAL after Step 4).
```hcl
resource "aws_vpc_security_group_ingress_rule" "r" {
  security_group_id = "sg-1"
  cidr_ipv4 = "0.0.0.0/0"
  from_port = 22
  to_port = 22
  ip_protocol = "tcp"
}
```

**P4** — expected: no `SEC-AWS-SG-001`. (The heredoc must contain the
literal `cidr_blocks = ["0.0.0.0/0"]` to reproduce today's false positive.)
```hcl
resource "aws_security_group" "sg" {
  name        = "sg"
  description = <<EOT
ingress {
  cidr_blocks = ["0.0.0.0/0"]
}
EOT
}
```

**P5** — expected: `COST-AWS-RISK-001`. (The `tags` map must be multi-line;
the one-line form already fires today.)
```hcl
resource "aws_cloudwatch_log_group" "l" {
  name = "l"
  tags = {
    retention_in_days = "none"
  }
}
```

**P6** — expected: `SEC-AWS-SG-001` at CRITICAL.
```hcl
resource "aws_security_group" "sg" {
  name = "sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```
