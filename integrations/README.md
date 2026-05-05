# tf-analyze integrations

Drop-in configs for running `detect.py` in pre-commit, GitHub Actions, and other CI systems.

## Pre-commit hook

Local fast-feedback — runs on every `git commit` against changed `.tf` files.

**Install:** merge the `hooks:` entry from `pre-commit-hook.yaml` into your `.pre-commit-config.yaml` under a `repo: local` block. The file ships as a single hook definition (not a full config), so it nests cleanly under any existing `repos:` list.

**Skill path resolution:** the hook reads `$TF_ANALYZE_SKILL_ROOT` and falls back to `$HOME/.claude/skills/tf-analyze` (the standard Claude Code location). If you've cloned the skill elsewhere, export the variable in your shell rc file or pass it via a CI secret:

```sh
export TF_ANALYZE_SKILL_ROOT=/opt/skills/tf-analyze
```

The fallback path is silently used if the env var is unset, which is the right behaviour for the common case but can mask a missing install — the hook will fail with a Python `FileNotFoundError` rather than a "tf-analyze didn't run" silent pass, so failures are visible.

**Behavior:** diff mode only scans changed files. `--fail-on HIGH` blocks commits with HIGH or CRITICAL findings.

**Tuning:**

- Too strict? Raise to `--fail-on CRITICAL`.
- Too slow? Add `--only-fixture` exclusions or run on a `.tf` file subset via pre-commit's `files:` regex.
- Need to bypass once? `git commit --no-verify` (but do NOT make this the norm — fix the finding).

## GitHub Actions

Full CI integration with SARIF upload to Code Scanning and an HTML artifact for manual review.

**Install:** copy `github-action.yml` into `.github/workflows/tf-analyze.yml`.

**Behavior:**

- **PR runs:** diff mode — only changed files scanned. Fails the job on HIGH+ findings.
- **Main/master push:** full static scan. Always uploads SARIF + HTML report.
- **SARIF upload:** findings appear in the repo's Security → Code Scanning tab, with line-level annotations on the PR diff.

**Prerequisites:**

- `security-events: write` permission (already in the workflow).
- Public repo OR Advanced Security enabled (for Code Scanning uploads).
- Python 3.12 on the runner (stdlib only — no pip install needed).

## Verify-fixed workflow

After addressing findings from a prior report, run:

```bash
python3 ~/.tf-analyze/scripts/detect.py \
  --target . \
  --mode verify-fixed \
  --prior-report reports/tf-analysis-2026-04-01.md
```

This parses the prior report, re-probes each finding's location, and writes a new markdown report showing: `FIXED`, `STILL PRESENT`, or `MOVED`. Useful for audit trails and for asserting fixes landed before deleting the follow-up ticket.

## Other CI systems

The core invocation is just a single `python3` call with stdlib-only dependencies, so adapting to GitLab CI, CircleCI, Buildkite, etc. is trivial:

```bash
python3 scripts/detect.py --target . --mode diff --format sarif --fail-on HIGH
```

Exit code `0` = clean; exit `1` = findings at or above `--fail-on`; exit `2` = configuration error.
