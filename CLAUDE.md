# tf-analyze — project instructions

Terraform static-analysis engine. Stdlib-only Python; flat top-level modules
in `scripts/` that import each other directly (`from _hcl import ...`).
Entry point: `detect:main`. Rules ship as the `tf_analyze_catalog` data package.

## Verify before pushing
`main` requires the pytest matrix, the extension job, both docs-drift jobs, and
the stub-age job — so those gate merge. Run them locally anyway (faster than a CI
round-trip), and note the **`terragoat` snapshot gate is NOT required**, so its
check can only be caught here:

    pytest tests/ --tb=short -q              # full suite — the highest-ROI guard
    python3 scripts/self_test.py             # rule fixture round-trips
    python3 scripts/test_schema.py           # catalogue schema regression
    python3 scripts/detect.py --target . --strict-catalog --list-rules >/dev/null
    python3 scripts/check_attack_drift.py    # ATT&CK ↔ catalogue
    python3 scripts/gen-cli-docs.py --check  # only if you touched a CLI flag
    python3 scripts/gen_rule_docs.py --check # only if you touched catalogue docs
    python3 scripts/check_terragoat_snapshot.py  # NOT gated by CI — run it here

A new rule is a ~6-file PR (catalog YAML + fixture + terragoat trigger +
2 READMEs + maybe a CI snapshot bump). See CONTRIBUTING.md for the full flow.

## Hard invariants — violating these has already caused regressions
- HCL has **no single-quoted strings**. Never treat `'` as a string delimiter.
- Any brace/paren walker over *raw* HCL must be comment-aware (`#`, `//`, `/* */`).
- Catalogue YAML: **block-style lists only** (`- a`), never inline `[a, b]`.
- stdlib-only. The only optional dep is `python-hcl2`, gated by `--use-hcl2`.
- If a module runs as `__main__` and siblings do `from detect import ...`,
  alias `sys.modules.setdefault("detect", sys.modules[__name__])` first.

## VS Code extension
Bumping `vscode-extension/package.json#version` is not done until the 3
live-version docs and a dated CHANGELOG entry are updated in the same commit.
See CONTRIBUTING.md → "VS Code extension version sync".

## Pointers (don't duplicate these here)
- Adding rules / pattern kinds / graph checks → CONTRIBUTING.md
- Skill spec / output contract → SKILL.md
- Active backlog → tasks/TODO.md ; recorded gotchas → tasks/lessons.md
