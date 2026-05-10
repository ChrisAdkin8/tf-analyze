# tf-analyze virality plan — 2026-Q2

> **Local-only.** This file is excluded from version control via `.gitignore`. It's a working strategy doc, not a public artefact. Move sections to public docs (`docs/launch/release-notes.md`, blog posts, the project README) once they're decided rather than discussed.

## Executive summary

tf-analyze is feature-rich relative to existing users but invisible to strangers. The viral mechanic for developer tools is **user does X → sees a result → shares the result.** tf-analyze has the *moment* (adversarial narratives, attack graph, Module Reuse ROI) but no shareable artefact and no public surface where strangers encounter it.

**The single highest-leverage gap is `tfanalyze.com/scan/<owner>/<repo>` — a public web scanner that produces shareable URLs.** Everything else in this plan compounds from it. Without it, badges, demos, and state-of-IaC reports amplify a tool with no public surface.

---

## Framing — what virality looks like for this product

Every viral developer tool of the last decade (k9s, Bun, uv, Cursor, Aikido, tfsec) has the same shape:

1. A **one-line claim** users repeat to colleagues
2. A **30-second demo** with a visible "wow" moment
3. **Lower friction than the incumbent** (install, learning, time-to-value)
4. **A shareable artefact** — screenshot, GIF, score, badge, leaderboard

tf-analyze has #1 ("the only Terraform scanner that explains how the breach happens") and most of #2 (the Capital-One narrative on hover, the attack-graph view) but is missing #3 and #4. Closing those is the strategy.

---

## Ranked feature gaps (highest viral leverage first)

### #1 — `tfanalyze.com/scan/<owner>/<repo>` public web scanner

**This is THE load-bearing feature. Everything else compounds from it.**

The mechanic: paste a public GitHub URL, the backend clones+scans+caches, returns a permalink to a styled report (score, grade, attack graph SVG, top findings with adversarial narratives, MITRE summary). Each scan produces a URL the user shares. Each share is an organic referral.

Comparable proven-viral patterns:
- `snyk.io/test/github/<repo>` — what we're trying to be the IaC version of
- `goreportcard.com/report/<repo>` — same shape, sustained 8 years on word-of-mouth
- `pkg.go.dev/<package>` — proof a docs site becomes viral when it's THE canonical URL

**Already done:** `demo/` is a FastAPI app with the engine wired in; `--format html` produces a styled self-contained report; engine completes a real scan in <5s on most repos; risk score + grade are deterministic and quotable; attack-graph SVG export already exists.

**Missing to launch:**
- Hosting (Fly.io — `demo/fly.toml` suggests this was already the chosen path)
- Domain (`tfanalyze.com` or similar)
- Clone-and-scan worker with caching keyed on commit SHA
- Rate limiting + GitHub OAuth for higher-rate access on logged-in users
- Per-repo scoring history (URL shows trend, not just a snapshot)

**Effort:** ~2 weeks for MVP. **Viral coefficient:** every shared scan URL is a fresh referral.

### #2 — `tfanalyze.com/badge/<owner>/<repo>.svg` README badge

Coupled with #1, the multiplier. Every README that embeds the badge is a permanent backlink + a fresh referral every time someone scrolls past it.

`[![tf-analyze](https://tfanalyze.com/badge/myorg/myrepo.svg)](https://tfanalyze.com/scan/myorg/myrepo)` renders as `tf-analyze: A · 96`. Click → full report. shields.io proved this format is friction-free; users will do it themselves once one popular repo does it.

**Effort:** 2 days on top of #1. **Viral coefficient:** compounding — each badge in a popular repo's README produces N referrals/day proportional to that repo's traffic.

### #3 — A 90-second demo video

Highest-converting marketing asset for developer tools. Cursor's launch was fueled by 30-second demo GIFs. Bun's launch was a single benchmark image.

What the video shows:
- 0–10s: open `examples/attack-graph-demo/` in VS Code. Six status-bar shortcuts appear. Score: 19 (D).
- 10–25s: hover over `aws_iam_role`. Capital One narrative appears in the tooltip.
- 25–45s: click 🛤 Attack Graph. d3 view renders INTERNET → EC2 → IAM-role → S3.
- 45–70s: click 🪄 Remediate. Diff preview shows fixes for 8 findings. Apply.
- 70–90s: score visibly climbs from 19 (D) to 73 (B). Final caption: `code --install-extension tfanalyze.tf-analyze`.

Post to: r/Terraform, r/devops, dev.to, Hacker News (Tuesday 9am PT), HashiConf, the project README at the top.

**Effort:** 1 day to record + edit. **Viral coefficient:** asymmetric — most videos die, the ones that catch get 100x what your README gets.

### #4 — State-of-IaC quarterly report

Run tf-analyze across the top 1000 public Terraform repos on GitHub (filtered to repos with >100 stars + recent commits). Publish aggregate findings as a blog post + downloadable PDF.

The headlines write themselves:

> "73% of public Terraform repos have at least one HIGH-severity IAM finding. The most common: `Resource = "*"` in IAM policy documents — the same configuration that caused the Capital One 2019 breach."

> "Of the top 100 community modules on the Terraform Registry, 12 hand-roll a VPC that could be replaced by `terraform-aws-modules/vpc/aws` — saving an average of 85 lines per module."

GitGuardian became a known brand by publishing the State of Secrets Sprawl annually. Same playbook.

**Effort:** 3 weeks for the first edition; 1 week per subsequent quarter. **Viral coefficient:** one wave of press per publication; cumulative authority over time.

### #5 — Trivy plugin

`trivy plugin install tf-analyze` puts you in front of every Trivy user (multi-million install-base). Plugin contract is small (a JSON spec + a binary). Single-file binary distribution from the publication backlog is the prerequisite.

**Effort:** 1 week assuming the binary ships first. **Viral coefficient:** highest single-step distribution multiplier.

---

## Smaller compounding gaps (days, not weeks each)

| Gap | Why | Effort |
|---|---|---|
| VS Code Quick Open ranking | `keywords` already includes `tfsec`. Add `checkov`, `terragoat`. Users searching for the dominant tool discover the alternative. | 5 min |
| `.vscode/extensions.json` PRs to community modules | Anyone who clones the module sees the recommendation. Submit to top 10 `terraform-aws-modules/*`. | 1 day |
| Adversarial-narrative bot | Daily Twitter/Mastodon/LinkedIn post auto-generated from `_ATTACK_NARRATIVES`. Never runs out of content. $0/mo to run. | 1 day |
| OWASP IaC Top 10 mapping page | One docs page mapping every catalogue rule. Becomes the canonical "OWASP IaC compliance" reference. Credibility lever for enterprise buyers. | 2 days |
| MCP server visibility | Round 28 shipped one. Few people know. Submit to Cursor / Continue / Claude Code MCP registries. Add a README section. Brand-new channel; almost zero competitors. | 2 days |
| `tf-analyze drift` | Compare static analysis to `terraform show -json state.tfstate`. Different audience (oncalls / SREs vs. PR reviewers). Differentiates from tfsec/checkov. | 1 week |
| Compliance PDF export | CISO-targetable artefact. Style the existing compliance gap report as printable PDF with logo + signed timestamp. | 3 days |
| Browser extension | Overlay tf-analyze findings on `.tf` files viewed on GitHub. Smaller market but high engagement per user. | 2 weeks |

---

## What I'd specifically NOT build

- **More rules.** 215 is enough; rule #216 doesn't drive any virality.
- **More clouds.** AWS/GCP/Azure cover 95% of the market.
- **LLM-driven anything.** The deterministic engine is the differentiator. Cursor's mistake was making everything AI; the half that should be AI gets dragged down by the half that shouldn't.
- **Freemium tier.** Kills community trust early. tfsec + checkov stayed free; users tolerated Aqua's later monetisation only because the core stayed open. Don't break that contract.
- **Enterprise dashboard.** Premature. Build it after the first 10 paying logos ask, not before.
- **Rewriting the engine in Go/Rust.** Tempting, won't move the virality needle. Single-binary distribution via PyOxidizer gets you the install-friction win without the rewrite cost.

---

## 90-day plan

| Week | Action | Gates |
|---|---|---|
| 1 | Click "Publish to Marketplace" on existing v0.2.1 release. Submit pre-commit-hooks PR. Bind `v1` tag. | None — backlog drain |
| 2 | Single-binary via PyOxidizer. Publish to GitHub Releases + Homebrew tap. | Week 1 published |
| 3–4 | `tfanalyze.com/scan/<owner>/<repo>` MVP on Fly.io. Cache by commit SHA. | None — independent |
| 5 | Score badge SVG. Submit one PR adding the badge to a popular community module's README. | Weeks 3–4 must work |
| 6 | Record + post 90-second demo video. HN submission Tuesday 9am PT. | Weeks 3–4 (use scan URL in CTA) |
| 7–8 | Trivy plugin. | Week 2 binary |
| 9–10 | First state-of-IaC report. Run scan across top 1000 public TF repos. Write the blog post. | Week 2 binary (for batch scanning) |
| 11 | MCP server visibility blitz. Submit to Cursor / Continue / Claude Code MCP registries. | None |
| 12 | OWASP IaC Top 10 mapping page. State-of-IaC press cycle continues. | None |

**Critical path: weeks 3–4.** If `tfanalyze.com/scan` doesn't ship and isn't great, every downstream item is amplifying a tool with no public surface. With it, every other item compounds.

---

## Meta-observation

The publication-vs-engineering tension has recurred across at least four conversation rounds (Round 24 distribution analysis, the HCSEC question, the module-replacement-remediate question, this one). The pattern: I propose feature X, the right answer is "ship what's already done first." Whenever tempted to build something new, check whether the thing already done has been *published*. Almost always, that's the higher-leverage move.

The publication backlog as of 2026-05-10:
- [ ] GitHub Marketplace listing for the Action — engineering complete since 2026-05-08; one operator click on the v0.2.1 release page
- [ ] VS Code Marketplace listing — engineering complete; needs `vsce publish` against the `tfanalyze` publisher account
- [ ] Open VSX listing (Cursor / VSCodium / Theia coverage) — same `.vsix`, different registry
- [ ] pre-commit.com hooks index submission — `.pre-commit-hooks.yaml` already exists in the repo
- [ ] Single-binary distribution
- [ ] Public web scanner (this plan's #1)
- [ ] Trivy plugin (gated on single-binary)

When this list is empty, build the next thing on the feature side. Until then, the answer to "what should we build?" is "publish what's already done."
