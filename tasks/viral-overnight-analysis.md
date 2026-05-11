# Overnight deep analysis — `/schedule` prompt

Two axes: (1) viral-features research, (2) repo health audit (robustness, documentation, maintainability). Review, then schedule with:

```
/schedule run "tf-analyze overnight deep analysis" at 2026-05-10T23:00 once
```

(or `at 2026-05-11T02:00` if you want a quieter slot)

When prompted for the agent prompt, paste the **PROMPT** block below verbatim.

---

## PROMPT

You are running an unattended deep analysis of the `tf-analyze` repo at `/Users/chris.adkin/Projects/tf-analyze`. Two deliverables, both written to `tasks/overnight-analysis-<today>.md` (use today's date at runtime):

1. A ranked, evidence-backed list of features that would drive viral adoption.
2. An honest audit of the codebase's robustness, documentation, and maintainability — what's brittle, what's undocumented, what will be painful in 6 months.

The two axes inform each other: a tool that goes viral and then collapses under maintenance debt is a worse outcome than one that grows slower on solid foundations. Surface that tension explicitly when it appears.

### Constraints

- **Budget**: spend at most 4 hours of wall-clock and ~$30 of model spend. If you approach either, stop the current subagent fan-out, synthesize what you have, and write the report.
- **Honesty rule**: every recommendation must cite the file path, URL, or commit SHA you read. No plausible-sounding claims without a source. If you couldn't verify something, say so.
- **No code changes.** This is research only. Do not edit source files outside `tasks/`.
- **Git: report-only branch.** You may create a branch named `overnight-analysis/<today>` (e.g. `overnight-analysis/2026-05-11`), commit the single report file `tasks/overnight-analysis-<today>.md` to it, and `git push -u origin overnight-analysis/<today>`. That is the ONLY git operation permitted. Do not touch `main`, do not merge, do not open a PR, do not push anything else. If the branch already exists, append `-2`, `-3`, etc. — never force-push.
- **Commit message**: `docs(overnight): viral + repo-health analysis <today>` with a one-line body summarizing the highest-priority finding. Sign-off line `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`.
- **Respect existing memory**: read `~/.claude/projects/-Users-chris-adkin-Projects-tf-analyze/memory/MEMORY.md` and the linked memory files first. The user already has a virality strategy in `project_virality_strategy.md` — your job is to **stress-test and extend** it, not rediscover it.

### Phase 1 — Ground truth (sequential, ~25 min)

Read these to establish what's actually shipped and what shape the code is in:

- `README.md`, `PLAN.md`, `TODO.md`, `CHANGELOG.md`
- `scripts/detect.py` (top-level structure only — do not read all 10k+ lines; note total line count, top-level function/class inventory, obvious hotspots)
- `scripts/_scoring.py`, `scripts/_versions.py` (newer files, smaller — read in full)
- `vscode-extension/package.json`, `vscode-extension/CHANGELOG.md`
- `tests/` directory listing — note which surfaces have tests and which don't
- `docs/` directory listing
- `examples/` directory tree
- `~/.claude/projects/-Users-chris-adkin-Projects-tf-analyze/memory/MEMORY.md` and every linked file

Note in working memory: shipped surfaces, current rule count, latest VS Code version, demo corpora present, claimed-vs-actual gaps, file sizes / LOC distribution, test-to-code ratio.

### Phase 2 — Parallel research fan-out (~150 min)

Launch these **five subagents in a single message** (parallel):

**Subagent A — Repo audit (Explore):**
> Audit tf-analyze's actual surface area vs. what `memory/project_virality_strategy.md` claims is shipped. For each of the 12 ranked items in the strategy doc, classify as: Shipped / Partially shipped / Not started, with file/commit evidence. Identify any surfaces that exist but aren't mentioned in the strategy. Report under 400 words.

**Subagent B — Competitor landscape (general-purpose, WebSearch + WebFetch):**
> Research the IaC analyzer market as of 2026-Q2. For each of: Checkov, tfsec (now Trivy), KICS, Terrascan, Snyk IaC, Bridgecrew, Wiz IaC — find:
> (1) GitHub stars and 90-day delta
> (2) Last 3 release notes' headline features
> (3) Marquee feature tf-analyze lacks
> (4) One thing tf-analyze does that they don't
> Cite URLs for everything. Report as a table.

**Subagent C — Viral launch patterns (general-purpose, WebSearch sequential — do NOT spawn nested parallel WebSearch):**
> Find 5 dev-tool repos that went from <500 to >5000 GitHub stars in 2025–2026. For each: the launch artifact (blog post / video / HN thread URL), the hook, the distribution channel, and the timing. Look especially for static-analysis / security / DX tools. Extract the **transferable pattern** — what would tf-analyze need to copy. Cite every claim. Report under 600 words.

**Subagent D — Public-scanner feasibility (Plan):**
> The load-bearing feature in the strategy is `tfanalyze.com/scan/<owner>/<repo>`. Read `scripts/detect.py`, `vscode-extension/`, the badge service, demo corpora, and any `demo/` or `web/` directories. Identify: what already exists, what the smallest shippable cut is, and the concrete missing pieces (deploy target, auth/abuse, caching, rendering). Estimate effort in days. Report a 1-week plan.

**Subagent E — Repo health audit (Explore + targeted Read):**
> Audit the `tf-analyze` codebase for **robustness, documentation, and maintainability**. Three sub-deliverables:
>
> **(E1) Robustness.** Where will this break? Look for: unhandled exception paths, silent `except: pass`, missing input validation at the CLI/LSP/MCP boundaries, brittle parsing (HCL edge cases — heredocs, dynamic blocks, nested for_each), test coverage gaps for negative paths, race conditions in the VS Code extension, version-drift risks (Python, Node, Terraform versions in CI vs. supported), what happens on malformed/huge/binary input. Cite the exact file:line for each finding. Cross-reference `tests/` to see what's actually covered. Rank top 10 robustness risks by (likelihood × blast radius).
>
> **(E2) Documentation.** Audit: README freshness vs. shipped surfaces (does the Quickstart actually work today?), per-rule docs site coverage and accuracy, inline docstrings in `scripts/detect.py` (sample 10 functions — are they helpful or stale?), VS Code extension README, `docs/` completeness, missing CONTRIBUTING / ARCHITECTURE / SECURITY.md. Identify: top 5 documentation gaps that would block a new contributor, and top 3 that would mislead a current user.
>
> **(E3) Maintainability.** `scripts/detect.py` is the elephant — get its line count, top-level symbol count, and identify the 3–5 largest internal functions/regions. Is the recent split (`_scoring.py`, `_versions.py`) the start of a sustainable pattern, or is the rest of the file resisting decomposition? Check: dependency hygiene (`requirements.txt`, `pyproject.toml`, `vscode-extension/package.json` — pinned vs. floating, security advisories?), CI surface (what's gated, what isn't — note the `project_round28_summary.md` warning that there are no required checks), test pyramid shape (unit vs. integration vs. fixture-based), naming consistency, dead code, circular imports. Top 5 refactors ranked by (pain reduction × inverse risk).
>
> Cite file:line for every finding. Report under 1200 words across all three sub-deliverables. Be honest — if the code is in good shape, say so; don't manufacture concerns.

### Phase 3 — Synthesis (you, the orchestrator, ~40 min)

Combine all five reports into `tasks/overnight-analysis-<today>.md` with these sections:

1. **Ground truth** — what's actually shipped vs. claimed (from A)
2. **Where the market is** — competitor table + the gap tf-analyze should own (from B)
3. **What viral launches look like in 2026** — patterns + the one tf-analyze should copy (from C)
4. **The load-bearing feature, costed** — public scanner 1-week plan (from D)
5. **Ranked viral recommendations** — top 5 features by (viral lift × inverse build cost). For each:
   - Concrete deliverable (1 sentence)
   - 1-week implementation sketch (≤5 bullets, naming the files/services touched)
   - One **falsifiable** success metric (e.g. "≥500 GH stars within 30 days of launch", not "more visibility")
   - Honest risk: what kills it
6. **Repo health — robustness** — top 10 risks ranked, file:line cited (from E1)
7. **Repo health — documentation** — top 5 contributor-blocking gaps + top 3 user-misleading gaps (from E2)
8. **Repo health — maintainability** — `detect.py` decomposition status, dependency hygiene, CI gaps, top 5 refactors ranked (from E3)
9. **Cross-axis tension** — where viral acceleration would worsen repo health, and which fixes are prerequisites for which launches. Be specific: "ship feature X only after refactor Y" with reasoning.
10. **Combined 90-day plan** — interleave the viral roadmap with the must-do robustness/docs/maintenance work. Mark each item as `[viral]`, `[health]`, or `[both]`. The user already has a viral 90-day plan in `memory/project_virality_strategy.md` — your version should incorporate or explicitly override it.
11. **What to NOT build / NOT fix** — explicit no-go list with reasoning (covers both axes)
12. **Open questions** — things you couldn't resolve and what evidence would resolve them

### Output requirements

- Markdown only. No emojis (the user's CLAUDE.md prohibits them unless asked).
- Total length: 3000–5000 words. If you're shorter, you're under-researched; if longer, you're padding.
- End with a **Verification report**: list each of the 12 sections, the subagent(s) that fed it, and one cited fact from each.
- If a subagent fails or returns nothing, note it in the report — do not silently drop a section.

### Final delivery (mandatory — do not skip)

1. Write the report to `tasks/overnight-analysis-<today>.md`.
2. `git checkout -b overnight-analysis/<today>` (if exists, suffix `-2`, `-3`, etc.).
3. `git add tasks/overnight-analysis-<today>.md` — ONLY this file. Verify with `git status` that nothing else is staged.
4. Commit with the message defined in Constraints.
5. `git push -u origin overnight-analysis/<today>`.
6. In your final orchestrator message, output: the branch name, the commit SHA, and the first 500 words of the report inline (so the user sees the gist in the run transcript without opening the branch).

### What to do if you get stuck

- If WebSearch quota exhausts mid-run, fall back to WebFetch on specific known URLs (GitHub releases pages, HN front page archives).
- If you hit the budget cap, stop the next planned subagent, write what you have, and flag the gap in "Open questions."
- Do **not** invent data to fill a section. An empty section with "research incomplete: ran out of budget" is correct behavior.

---

## Notes for the human (not part of the prompt)

- The `/schedule` skill creates a remote agent — your laptop can be closed.
- One-shot scheduling is supported; this doesn't need to recur.
- You'll get a notification (or can `/schedule list`) to find the result.
- If the report is thin, the failure is almost always Phase 2 subagent prompts — tighten those, not the orchestrator prompt.
- Time cap is 4h / $30. Subagent E adds real research load; if the run lands at the cap with E1/E2/E3 thin, bump the budget rather than dropping the axis.
