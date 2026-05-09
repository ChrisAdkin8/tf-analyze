# Launch artefacts

Materials prepared for the v0.1.0 public launch. None of these have
been posted yet — each is a draft for the launch operator to review,
adjust to taste, and submit on the day.

| File | Where it lands | Status |
|------|----------------|--------|
| [`release-notes.md`](release-notes.md) | GitHub Releases page (auto-attached by `release.yml` when `v*.*.*` is pushed) | Drafted |
| [`hacker-news.md`](hacker-news.md) | https://news.ycombinator.com/submit (Show HN) | Drafted |
| [`reddit-terraform.md`](reddit-terraform.md) | https://www.reddit.com/r/Terraform/submit | Drafted |
| [`pre-commit-hooks-pr.md`](pre-commit-hooks-pr.md) | PR description for https://github.com/pre-commit/pre-commit-hooks | Drafted |
| [`fly-deploy.md`](fly-deploy.md) | Fly.io deployment commands for `demo/` | Drafted |
| [`launch-checklist.md`](launch-checklist.md) | Operator-facing checklist for the launch day | Drafted |

## Order of operations

1. **Tag and push v0.1.0** — triggers the docker workflow + the release workflow. Manual marketplace toggle on the GitHub Release page (auto-detected because `action.yml` exists at repo root).
2. **Run `scripts/setup-repo-metadata.sh ChrisAdkin8/tf-analyze`** to set the GitHub repo description, homepage, and topics.
3. **`vsce publish`** the VS Code extension. Requires a verified Marketplace publisher account `tfanalyze`.
4. **`ovsx publish`** to Open VSX (Cursor / VSCodium reach).
5. **Deploy `demo/` to Fly.io** per [`fly-deploy.md`](fly-deploy.md).
6. **Record the LSP screen-cap GIF** — see the suggested script in [`launch-checklist.md`](launch-checklist.md). Embed it as the README hero replacing the static banner.
7. **Submit the pre-commit hooks PR** per [`pre-commit-hooks-pr.md`](pre-commit-hooks-pr.md).
8. **Post Hacker News + Reddit** per their respective drafts. Time the HN submission for Tuesday or Wednesday morning US Eastern (peak hour).
