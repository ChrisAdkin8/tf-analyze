# tf-analyze — Lessons

## brace_walk / HCL brace-matching must be comment-aware + double-quote-only (2026-05-29)

**Failure mode:** Routing `find_blocks` / `block_arg_value` / `_extract_terraform_version`
through the shared `brace_walk` (to fix `}`-inside-string truncation) introduced two test
regressions (`test_multi_file::test_module_input_flow_through`,
`test_examples_demos::test_graph_shape_matches_readme`). `brace_walk` tracked single-quote
state, and HCL comments commonly contain apostrophes (`# the child's bucket`), so a lone `'`
flipped it into fake "string mode" and the block's closing `}` was never counted → the block
silently failed to parse.

**Prevention rules:**
- HCL has **no single-quoted strings** — never treat `'` as a string delimiter in any HCL
  matcher. Double quotes only. (A test, `test_single_quoted_string_handled`, had pinned the
  wrong "defensive" behavior; it was corrected.)
- Any brace/paren walker over *raw* HCL (text that still contains comments) must be
  **comment-aware** (`#`, `//`, `/* */`) or the quotes/braces inside comments corrupt
  depth/quote state.
- The regression was caught only by the **full** suite, not the targeted unit tests. Run the
  whole `pytest` suite before declaring a change to a shared primitive done — and when it
  fails, `git stash` to confirm baseline vs. regression before theorizing.

## Prove a "changes nothing" refactor with a property snapshot, not just tests (2026-05-30)

**Context:** Splitting `detect.py`'s ~510-line argparse block into 12 `_add_*_args(ap)`
helpers (and extracting `_render_report` / `_run_detection` / the mode bodies out of
`main()`) is *supposed* to change nothing — but a move can silently drop a flag, reorder a
`choices` list, or change a `default`, and neither the `--help` smoke nor the CLI-docs drift
gate catches a changed default or a moved-but-still-present argument.

**Prevention rules:**
- For a structural move that should be behaviour-preserving, snapshot the observable property
  and assert equality across the change. For argparse: dump every action's `(dest,
  option_strings, default, choices, nargs, const, type, class)` tuple, sorted, before the edit
  and diff after — "all 57 actions identical" beats any number of behavioural tests. The
  CLI-docs gate covers help *text*; the spec snapshot covers *semantics*.
- Before extracting **un-covered** code out of `main()`, write a characterization test first
  (pin exit code / stderr markers / output structure against the live binary), confirm it
  passes on the *old* code, then move. Extract in an order where each slice is guarded by an
  existing or cheap-new test, and record the deliberate non-extractions (e.g. keeping `(emit,
  out_file)` as two params rather than one object) so the next person knows they were a
  choice, not an oversight.
