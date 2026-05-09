# Launch-day operator checklist

Print this. Tick the boxes in order. Each one unblocks the next.

## Tag and ship

- [ ] **Working tree clean** — `git status` returns nothing.
- [ ] **All tests green** — `python3 -m pytest tests/ -q` returns 0.
- [ ] **Tag locally** — `git tag v0.1.0 -m "Initial public release: 209 rules, 411 tests, 100% fix_hcl"`.
- [ ] **Push the tag** — `git push origin v0.1.0`. Triggers `docker.yml` (multi-arch publish) + `release.yml` (GitHub Release with .vsix attached).
- [ ] **Verify GHCR image exists** — `docker pull ghcr.io/chrisadkin8/tf-analyze:v0.1.0`.

## GitHub repo presentation

- [ ] **Run `scripts/setup-repo-metadata.sh ChrisAdkin8/tf-analyze`** — sets description, homepage, topics. Requires `gh` CLI authenticated.
- [ ] **Toggle "Publish to Marketplace" on the v0.1.0 GitHub Release page** — checkbox appears because `action.yml` exists at repo root.
- [ ] **Verify Marketplace listing** — https://github.com/marketplace/actions/tf-analyze should resolve.

## VS Code Marketplace

- [ ] **Register publisher account `tfanalyze`** at https://marketplace.visualstudio.com/manage. Verify your Microsoft account.
- [ ] **Get a Personal Access Token** — Azure DevOps → User Settings → Personal Access Tokens → "Marketplace - Manage" scope.
- [ ] **`vsce login tfanalyze`** with the PAT.
- [ ] **`cd vscode-extension && npx vsce publish`**. Validates the .vsix; uploads it.
- [ ] **Verify listing** — https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze should resolve.

## Open VSX (Cursor / VSCodium)

- [ ] **Sign in at https://open-vsx.org/user-settings/extensions** with GitHub.
- [ ] **Generate access token** under "Tokens".
- [ ] **`npx ovsx publish tf-analyze-0.1.X.vsix -p $OVSX_TOKEN`**.
- [ ] **Verify listing** — https://open-vsx.org/extension/tfanalyze/tf-analyze.

## Web demo

- [ ] **Follow [`fly-deploy.md`](fly-deploy.md)** end-to-end. Demo at https://demo.tf-analyze.dev (or chosen URL).
- [ ] **Smoke test the JSON API** with the curl recipe in fly-deploy.md.
- [ ] **Update README hero CTA** to link the live demo.

## Hero GIF

The README badge row + comparison table is fine, but the README
hero is still the static SVG banner. The differentiator is the
LSP-real-time-narrative demo — there's no shareable artefact for
that yet.

Suggested 30-second screen recording:

1. Start in VS Code with an empty `main.tf` open.
2. Type `resource "aws_iam_user" "admin" {`, paste:
   ```hcl
   policy = jsonencode({
     Version = "2012-10-17"
     Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
   })
   ```
3. **Pause** — squiggle appears within 200ms (LSP). Hover.
4. **Pause** — narrative panel shows the Capital One breach citation.
5. Click `⌘.` → Quick Fix → "Apply fix for SEC-AWS-IAM-JSON-003".
6. **Pause** — file is patched, squiggle clears.
7. Click the **🛤 Attack Graph** status-bar shortcut.
8. **Pause** — d3 graph animates in, INTERNET → role → DB visible, critical edge red.

Tools:
- macOS: built-in `⌘⇧5` screen record, then convert via `ffmpeg -i input.mov -vf "fps=15,scale=900:-1:flags=lanczos" -c:v gif output.gif`.
- Or [`vhs`](https://github.com/charmbracelet/vhs) for a scripted
  recording. A `.tape` file would let us reproduce the GIF on each
  release.

Embed in README hero:
```markdown
<p align="center">
  <img src="docs/images/lsp-narrative-demo.gif" alt="tf-analyze LSP demo" width="900">
</p>
```

## Pre-commit hooks index

- [ ] **Open the PR** per [`pre-commit-hooks-pr.md`](pre-commit-hooks-pr.md).
- [ ] **Wait for merge** (typically 1–3 days).
- [ ] **Verify** at https://pre-commit.com/hooks.html (search "tf-analyze").

## Hacker News + Reddit

- [ ] **Schedule for Tuesday 8:30 AM ET** (peak HN slot).
- [ ] **Post per [`hacker-news.md`](hacker-news.md)**.
- [ ] **Post r/Terraform per [`reddit-terraform.md`](reddit-terraform.md)**, ≥ 4 hours later.
- [ ] **Available to respond** for 6 hours after each.

## Communications

- [ ] **HashiCorp Discuss thread** in the Terraform forum.
- [ ] **LinkedIn announcement** with the GIF + 1-sentence hook.
- [ ] **Personal Twitter/X** with the same GIF.
- [ ] **Email a few security-twitter folks who write about IaC** for warm intros.

## After launch

- [ ] Add Marketplace install counts to a stats panel in README.
- [ ] Triage issues in priority order: false-positive reports first, install bugs second, feature requests third.
- [ ] Cut a v0.1.1 within 2 weeks if any P0 issues land — rapid response builds trust.
