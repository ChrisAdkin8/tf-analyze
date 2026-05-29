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
