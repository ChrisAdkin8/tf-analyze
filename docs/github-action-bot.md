# Auto-remediation PR bot

The auto-remediation bot at
[`integrations/github-action-bot.yml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/integrations/github-action-bot.yml)
is a Dependabot-shaped workflow for tf-analyze findings. It runs on a
schedule, applies safe (`fix_disruption: none`) HCL patches from the
rule catalogue, and opens **exactly one PR per scan** — grouped by rule
family, with a body that tells reviewers which findings the bot avoided
so they know what manual work remains.

It is distinct from the [GitHub Action](github-action.md): the Action
*gates* PRs at review time; the bot *opens* PRs proactively.

## See it live

A reference repo at
**[github.com/ChrisAdkin8/tf-analyze-bot-demo](https://github.com/ChrisAdkin8/tf-analyze-bot-demo)**
hosts five intentionally-vulnerable AWS resources annotated with the
rules that flag them, and the unmodified bot workflow installed at
`.github/workflows/tf-analyze-bot.yml`.

- 🔁 **[Live bot PR #1](https://github.com/ChrisAdkin8/tf-analyze-bot-demo/pull/1)** — opened by the first scheduled run. The `tf-analyze-bot/auto-fixes` branch is force-pushed and the PR body is upserted on every scan, so there is always at most one open. Click in to see the rendered body (rule-family grouping, what the bot avoided, links back to the per-rule docs). The [PR list](https://github.com/ChrisAdkin8/tf-analyze-bot-demo/pulls) shows the current state.
- 🏃 **[Workflow runs](https://github.com/ChrisAdkin8/tf-analyze-bot-demo/actions/workflows/tf-analyze-bot.yml)** — each scheduled or `workflow_dispatch` invocation is logged here.
- 📂 **[Seed bugs (`main.tf`)](https://github.com/ChrisAdkin8/tf-analyze-bot-demo/blob/main/main.tf)** — five fix-able resources, each commented with the rule ID it trips. The demo repo's [README](https://github.com/ChrisAdkin8/tf-analyze-bot-demo#seeded-issues--all-bot-fixable) lists rule IDs alongside their `fix_disruption` tier.

Fork the demo, fire the **Run workflow** button from the Actions tab,
and you'll see a fresh bot PR open within ~30 seconds.

## Install

Copy the workflow into your repo at `.github/workflows/tf-analyze-bot.yml`:

```bash
mkdir -p .github/workflows
curl -sSLo .github/workflows/tf-analyze-bot.yml \
  https://raw.githubusercontent.com/ChrisAdkin8/tf-analyze/main/integrations/github-action-bot.yml
git add .github/workflows/tf-analyze-bot.yml
git commit -m "ci: add tf-analyze auto-remediation bot"
git push
```

That's everything. No app install, no API token to configure — the
workflow uses `secrets.GITHUB_TOKEN` (auto-provisioned by GitHub) for
both the branch push and the `gh pr create` call.

## Inputs

The workflow exposes two `workflow_dispatch` inputs you can also bake
into the file for the scheduled runs:

| Input | Default | Effect |
|---|---|---|
| `max-disruption` | `none` | Highest `fix_disruption` tier the bot will apply. `plan_required` lets the bot apply changes that show in `terraform plan` but don't force replacement; **never** set to `forces_replacement` for an unattended bot. |
| `ref` | `main` | tf-analyze ref the bot installs (branch / tag / SHA). Pin to a release tag for reproducible behaviour. |

## Cadence

The default schedule is weekly — Mondays 03:00 UTC. Edit the `cron:`
line to taste:

```yaml
on:
  schedule:
    - cron: "0 3 * * 1"     # weekly Monday 03:00 UTC (default)
    # - cron: "0 3 1 * *"   # monthly: first of the month
    # - cron: "0 3 * * *"   # daily (warning: chatty)
```

Daily produces too many PRs; monthly lets fixes pile up. Weekly is the
calibrated default.

## Behavior

- **Idempotent branch.** The bot reuses `tf-analyze-bot/auto-fixes` and
  force-pushes on each run, so a stale proposed-fix PR is overwritten
  rather than spawning duplicates.
- **PR upsert.** If a PR for the branch already exists the body is
  edited in place via `gh pr edit`; otherwise a new PR is opened via
  `gh pr create`. Exactly one open PR per repo at any time.
- **No-op on clean.** When the apply step leaves the working tree
  unchanged the workflow emits `::notice::No non-disruptive fixes
  available; skipping PR.` and exits 0 — no empty PR is opened.
- **Self-trigger guarded.** `if: github.actor != 'tf-analyze-bot[bot]'`
  prevents the bot's own commits from kicking off another apply.
- **PR body composition.** [`render_pr_body.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/integrations/github-action-bot/render_pr_body.py)
  groups the fixes by rule family (`SEC-AWS-IAM-*`, `ROB-DRIFT-*`, …)
  and lists the findings the bot intentionally *skipped* (above the
  disruption cap or no `fix_hcl` snippet) so reviewers know what's left.

## What gets fixed — and what doesn't

A rule is bot-eligible when:

1. Its catalogue entry has a `fix_hcl` snippet the regex patcher can
   anchor (attribute-edit fixes land cleanly; entirely new sibling
   resources do not).
2. Its `fix_disruption` is `≤ max-disruption` input (default `none`).
3. The detection produced a file + line anchor for the patch.

Today that's roughly **150 of 238 active rules**. Each fix the bot
applies is documented at the
[per-rule docs site](rules/) so reviewers can read the rationale before
approving.

Deliberate non-goals:

- **No `forces_replacement` fixes.** Even when the `fix_hcl` is
  correct, forcing replacement on a stateful resource (RDS, ECS service,
  EBS volume) is destructive. The default cap of `none` blocks these
  entirely.
- **No edits to opted-out paths.** The bot honours the consuming repo's
  `.tf-analyze.yaml` `ignore_paths:`, so `examples/`, `fixtures/`, and
  deliberately-vulnerable training corpora stay untouched — assuming
  you've configured them.
- **No piecemeal PRs.** One PR per scan, full stop. Daily/weekly cadence
  + branch reuse keeps the review surface bounded.

## Permissions

The workflow declares:

```yaml
permissions:
  contents: write       # push the auto-fixes branch
  pull-requests: write  # open/edit the PR
```

`security-events` is **not** required — the bot does not upload SARIF.
That's the [GitHub Action](github-action.md)'s job.

## Testing locally

The PR-body renderer is a pure-function script that runs offline:

```bash
git clone https://github.com/ChrisAdkin8/tf-analyze.git /tmp/tf-analyze
python3 /tmp/tf-analyze/scripts/detect.py --target . --format json \
  > /tmp/scan.json
python3 /tmp/tf-analyze/scripts/detect.py --target . \
  --apply-fixes dry-run --apply-fixes-max-disruption none \
  2> /tmp/apply.stderr
python3 /tmp/tf-analyze/integrations/github-action-bot/render_pr_body.py \
  --scan-json /tmp/scan.json \
  --apply-summary /tmp/apply.stderr \
  --output /tmp/pr-body.md
cat /tmp/pr-body.md
```

Drift gates on the workflow YAML shape + unit tests on `compose_body()`
live in [`tests/test_github_action_bot.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/tests/test_github_action_bot.py).

## Related

- [GitHub Action](github-action.md) — PR-gating composite action (review-time, not proactive).
- [HCP Terraform Run Task](run-task.md) — pre-apply gate inside HCP.
- [Pre-commit hook](pre-commit.md) — block PRs at commit time.
- [Per-rule docs](rules/) — every rule's rationale, `fix_hcl`, and compliance mappings.
