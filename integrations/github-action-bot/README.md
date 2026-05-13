# tf-analyze-bot — auto-remediation PR bot (R31.2)

A GitHub Actions workflow that scans your Terraform repo on a schedule, applies safe (`fix_disruption: none`) HCL fixes from the rule catalogue, and opens a single PR grouped by rule family. Think Dependabot, for security findings.

## What it does

1. Runs weekly (Mondays 03:00 UTC by default — adjustable via the `cron:` in [`../github-action-bot.yml`](../github-action-bot.yml)).
2. Scans the repo via `detect.py --format json`.
3. Runs `detect.py --apply-fixes apply --apply-fixes-max-disruption none` (R31.2 engine flag — caps the patcher to non-disruptive fixes only; everything that would force resource replacement is intentionally skipped).
4. If the working tree changed, force-pushes to `tf-analyze-bot/auto-fixes` and opens a PR (or updates the existing one in place — at most one PR per repo).
5. PR body groups fixes by rule family (`SEC-AWS-IAM-*`, `ROB-DRIFT-*`, …) and tells reviewers exactly which findings the bot avoided so they know what manual work remains.

## Install

Copy [`integrations/github-action-bot.yml`](../github-action-bot.yml) into your own repo at `.github/workflows/tf-analyze-bot.yml`:

```bash
mkdir -p .github/workflows
curl -sSLo .github/workflows/tf-analyze-bot.yml \
  https://raw.githubusercontent.com/ChrisAdkin8/tf-analyze/main/integrations/github-action-bot.yml
git add .github/workflows/tf-analyze-bot.yml
git commit -m "ci: add tf-analyze auto-remediation bot"
```

That's everything — no API tokens, no separate app install, no secrets to configure. The workflow uses `secrets.GITHUB_TOKEN` (automatically provisioned by GitHub) for both the branch push and the `gh pr create` call.

## Customise

The workflow has two `workflow_dispatch` inputs you can also bake into the file for the scheduled runs:

| Input | Default | Effect |
|---|---|---|
| `max-disruption` | `none` | Highest `fix_disruption` tier the bot will apply. Setting to `plan_required` lets the bot apply changes that show in `terraform plan` but don't force replacement; **don't** set to `forces_replacement` unless you really trust the catalogue authors and your CI. |
| `ref` | `main` | The tf-analyze ref (branch / tag / SHA) the bot installs. Pin to a release tag for reproducible behaviour. |

To adjust the schedule, edit the `cron:` line:

```yaml
on:
  schedule:
    - cron: "0 3 * * 1"     # weekly Monday 03:00 UTC (default)
    # - cron: "0 3 1 * *"   # monthly: first of the month 03:00 UTC
    # - cron: "0 3 * * *"   # daily: every day 03:00 UTC (warning: noisy)
```

## What gets fixed

A rule is bot-eligible when:
1. Its catalogue entry has a `fix_hcl` (or `fix_hcl_minimal`) snippet that can be applied via the engine's regex-based patcher.
2. Its `fix_disruption` field is `none` (or `≤ max-disruption` input).
3. The detection produced enough context (file + line) to anchor the patch.

Today that's roughly **220 of 343 active rules**. Every fix the bot applies is also documented at the per-rule docs site (`chrisadkin8.github.io/tf-analyze/rules/<RULE-ID>/`) so reviewers can read the rationale before approving.

## What the bot deliberately won't do

- **No `fix_disruption: forces_replacement` fixes.** Forcing replacement on a stateful resource (RDS, ECS service, etc.) is destructive even when the catalogue's `fix_hcl` is correct. The default cap of `none` blocks these.
- **No fixes against deliberately-vulnerable training corpora.** The bot honours your repo's `.tf-analyze.yaml` (`ignore_paths:`) so it leaves `examples/` and `fixtures/` directories alone — assuming you've configured them.
- **No piecemeal PRs.** One PR per scan. If the bot has nothing to apply, it exits cleanly without opening anything.
- **No retriggering itself.** The workflow's `if: github.actor != 'tf-analyze-bot[bot]'` guard prevents the bot's own commits from kicking off a fresh apply run.

## Testing locally

The PR-body renderer is a pure-function script you can run by hand:

```bash
python3 scripts/detect.py --target . --format json > /tmp/scan.json
python3 scripts/detect.py --target . --apply-fixes dry-run --apply-fixes-max-disruption none \
    2> /tmp/apply.stderr
python3 integrations/github-action-bot/render_pr_body.py \
    --scan-json /tmp/scan.json \
    --apply-summary /tmp/apply.stderr \
    --output /tmp/pr-body.md
cat /tmp/pr-body.md
```

Test coverage: see [`tests/test_github_action_bot.py`](../../tests/test_github_action_bot.py) — drift gates on the workflow YAML shape + unit tests on `compose_body()`.
