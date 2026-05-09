# Contributing to tf-analyze

Thanks for your interest in extending `tf-analyze`. The skill is designed to be small, surgical, and well-tested — every change should preserve those properties.

## How to choose what to work on

Three signals point at high-leverage contributions:

1. **Stale stubs.** Run `python3 scripts/stub-status.py` — anything older than ~90 days is a candidate for promotion to `status: active`. Promoting a stub is the smallest possible PR shape: edit the YAML, fill in the `patterns:` field, add a fixture, run self-test, done.
2. **OWASP gaps in `examples/terragoat/`.** Each per-cloud README has a "Catalogue expansion roadmap" section listing rules that *should* fire on the corpus but don't yet. AWS has the longest list — we ship 3 active AWS rules but the corpus documents ~10 AWS-shaped anti-patterns.
3. **Issues labelled `good first rule`** (once such labels exist on the issue tracker) — these are intentionally narrow, well-scoped, and don't require deep familiarity with the codebase.

If you have a specific anti-pattern in mind that isn't covered, open an issue first — it's faster to align on the right pattern_kind and the right OWASP slot before writing the code.

## Adding a new rule

The minimum viable PR for a new rule:

1. **Scaffold:**
   ```sh
   python3 scripts/detect.py --new-rule SEC-MYDOMAIN-001
   ```
   Writes `catalog/SEC-MYDOMAIN-001.yaml` and `fixtures/sec_mydomain_001/main.tf` with TODO markers.

2. **Edit the catalogue YAML.** The required fields are documented in [`catalog/README.md`](catalog/README.md). Pattern kinds are listed there too — pick the simplest kind that captures the rule:
   - `resource_arg` if the check is "resource of type X has attribute Y matching regex".
   - `resource_missing_arg` if the check is "resource of type X lacks attribute Y".
   - `resource_present` / `data_source_present` if presence alone is the issue.
   - `hcl_attr` for nested-block attribute checks.
   - `resource_body_contains` if you need a regex over the resource body but want to scope by type.
   - `grep` only if the above don't fit; it's the least precise.
   - `graph_check` for cross-resource conditions (register a Python function in `_GRAPH_CHECKS`).

3. **Edit the fixture.** Minimum HCL that triggers the rule. Convention: header comment lists `# Expected findings: - RULE-ID URGENCY description`. If the fixture is a *negative* test (the rule should NOT fire), add `# Expected findings: NONE` and `# Guards against: RULE-ID`.

4. **Add a trigger to `examples/terragoat/<cloud>/<NN>_<owasp>.tf`.** Pick the OWASP category that best matches *why the rule matters* (not what it detects). Update the file's "Expected tf-analyze findings" header block.

5. **Run the test suite:**
   ```sh
   python3 scripts/self_test.py        # rule fixture round-trips
   python3 scripts/test_schema.py      # schema validator regression
   python3 scripts/gen-cli-docs.py     # regenerate docs/cli.md if you added a CLI flag
   python3 scripts/detect.py --strict-catalog --target . --list-rules > /dev/null
   python3 scripts/detect.py --explain SEC-MYDOMAIN-001  # sanity-check the rendered entry
   ```

6. **Update the per-cloud README's rule list** in `examples/terragoat/<cloud>/README.md`.

7. **Verify the CI gate.** The terragoat finding-count gate may need a bump in `.github/workflows/ci.yml` if the new rule pushes the per-cloud or total count outside the tolerance band.

A correctly-shaped PR for a new rule touches: 1 catalogue YAML, 1 fixture, 1 terragoat file, 2 READMEs (catalogue and per-cloud), and possibly 1 CI tolerance bump. ~6 files. If your PR touches more than that, consider splitting.

## Adding a new pattern kind

If your rule's logic doesn't fit any existing `pattern_kind`, add a new one. This is heavier but the path is well-trodden:

1. Add the kind handler in `scripts/detect.py`. Per-file kinds go in `detect_in_file`; corpus-level kinds in `detect_corpus`. Cross-resource kinds go in `_GRAPH_CHECKS` as a registered function.
2. Document the new kind in `catalog/README.md` (the table at the top).
3. Add at least one rule using the new kind, plus a fixture.
4. If the kind is generally useful, document it in the SKILL.md too.

Avoid adding a kind that's only used by one rule — usually that rule should use `grep` instead, or the kind should be designed broadly enough to be reused.

## Adding a new graph check

Cross-resource conditions live in `_GRAPH_CHECKS` (see existing entries: `logging_target_public`, `gke_nodepool_secure_boot`, `kms_location_parity`, `iam_member_breadth`). The pattern:

```python
def _graph_my_check(index: dict, all_files_text: dict) -> list[dict]:
    """One-line summary. Multi-line docstring explaining what cross-
    resource condition this catches and the real-world consequence.
    """
    out: list[dict] = []
    for addr, resource in index.items():
        if resource["type"] != "...":
            continue
        # Walk to a related resource via the regex extractor, look it
        # up in the index, check its attributes.
        ...
        out.append({
            "file": resource["file"],
            "line": resource["line"],
            "resource": addr,
            "context": "...",  # printed in the report
        })
    return out


_GRAPH_CHECKS = {
    ...,
    "my_check": _graph_my_check,
}
```

Then in the catalogue YAML:

```yaml
patterns:
  - kind: graph_check
    function: my_check
    description: |
      ...
```

The graph index is built once per scan via `_build_resource_index(all_files_text)`. If your check needs auxiliary indexing (a name → block map for a specific resource type), build it inside the function and document why it's not in the shared index.

## Adding a new applies_when clause

`applies_when` currently supports `min_provider: { name: version }` and `min_terraform: version`. To add a new clause type (e.g. `cloud: gcp`):

1. Extend `_entry_applies_to_providers` in `detect.py`. Default behaviour for an unknown clause should be permissive (return `True`).
2. Update the schema validator in `validate_catalog_entry` to recognise the new field — but don't reject unknown sub-fields, only validate the ones you know.
3. Update `catalog/README.md` and the SKILL.md.
4. Add a regression test in `scripts/test_schema.py`.

## Documentation conventions

- **README files** at the repo root and per-cloud terragoat dirs are the user-facing entry points. Lead with capabilities and quickstart; defer architecture and roadmap to lower sections.
- **Catalogue YAML `recommendation:`** fields should include a code example where one helps. Aim for ~10-30 lines of recommendation per entry — long enough to be actionable, short enough to read in one sitting.
- **OWASP framing** in `examples/terragoat/<cloud>/<file>.tf` headers follows the format already established (Cloud, vulnerability summary, real-world impact, expected findings, fix summary). Stay within OWASP 2021 categories — the discipline of "this rule fits A0N because…" forces good thinking.

## Blog posts

Blog posts live at `docs/blog/YYYY-MM-DD-<slug>.md`. They are versioned alongside the code so a post and the artefact it describes ship in the same commit. When a post quotes a specific version (status-bar layout, rule count, error message, CLI flag), it must:

1. Pin the version in the YAML frontmatter (`extension_version: 0.1.22`, `engine_version: …` as applicable). Future readers can see at a glance whether the post still describes current behaviour.
2. Use plain anchored links (`[v0.1.18 changelog entry](../../vscode-extension/CHANGELOG.md#0118--2026-05-09)`) rather than tagging "current state" without a date — the post will outlive the state.

If a post becomes outdated by a later release, prefer leaving it as-is with a banner at the top (`> **Note:** documents v0.1.22 behaviour. Status bar reorganised in v0.1.30 — see …`) rather than rewriting in place. Posts are historical record; documentation lives under `docs/*.md`.

## VS Code extension version sync

Whenever `vscode-extension/package.json#version` changes, every user-facing doc that quotes a `.vsix` filename must be updated in the same commit. The `.vsix` filename is the install command users copy-paste — leaving it pinned to a stale version sends new users to an artefact that no longer exists on the release page.

Files that hold the live `.vsix` filename (must always match `package.json#version`):

- `vscode-extension/README.md` — the marketplace-facing readme; the install command in **Quickstart**.
- `docs/vscode-extension.md` — the project-level docs; the install command under **Installation**.
- `README.md` — the project root readme; the integrations table row for "VS Code extension".

Files that legitimately hold *historical* `.vsix` references (do **not** update these on a version bump):

- `vscode-extension/CHANGELOG.md` — by design, each entry refers to the artefact that shipped at that version.
- `CHANGELOG.md` (project root) — same.
- `TODO.md`, `PLAN.md`, archived planning docs — historical, leave as-is.

A version bump is not finished until:

1. `package.json#version` is bumped.
2. The three live-version docs above quote the new `.vsix` filename.
3. `vscode-extension/CHANGELOG.md` has a new dated entry for the version (even if the only change is a version sync — say so explicitly so users know it's safe to skip).
4. `npm test` passes (25 tests at time of writing).
5. `npm run package` produces a `.vsix` matching the new version, and `code --install-extension <vsix>` succeeds locally.
6. The new `.vsix` artefact is attached to the GitHub release (or noted as a follow-up if release is gated).

Skipping any of (2)–(4) is a doc bug; skipping (5)–(6) is a release bug. Both are caught at review time.

## Testing conventions

- **Self-test must pass.** Adding a rule without a fixture is a defect; the CI gate catches it.
- **Negative fixtures matter.** `false_positive_*` fixtures guard against the rule firing on legitimate-looking code. If you can think of one in 30 seconds, add it.
- **Schema regression test.** Adding new schema fields (or constraints on existing ones) requires extending `scripts/test_schema.py` so that future regressions surface.
- **CLI doc determinism.** `scripts/gen-cli-docs.py --check` must pass. If you added a flag, regenerate.
- **Terragoat count gate.** Per-cloud and total counts in `.github/workflows/ci.yml` must reflect reality. Bump them in the same PR as the catalogue change.

## Style

- **Python:** stdlib only by default. The optional `python-hcl2` fast-path is the only third-party dependency the engine knows about, and it's gated by `--use-hcl2`. Don't add a new dependency without discussion.
- **Type hints** on public functions; existing code is partial — fill in as you touch.
- **Comments** explain why, not what. If the regex is non-obvious, say what edge case it's defending against — not "match the resource block".
- **YAML** uses block-style lists (`- foo` then `- bar`), not inline `[foo, bar]` — the minimal YAML loader doesn't parse inline lists correctly.

## Communication

For substantive changes (new pattern kinds, schema additions, new architectural choices), open an issue first. For small additions (new rules, fixtures, doc fixes), a PR directly is fine.

PR reviews focus on:
1. Does the rule catch what it claims to catch? (Run the fixture, run the corpus.)
2. Does the recommendation suggest a fix that *actually works* against the named provider version?
3. Is the OWASP categorisation defensible?
4. Are the per-cloud README updates consistent with the new state?
