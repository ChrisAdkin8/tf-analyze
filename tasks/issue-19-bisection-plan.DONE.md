# Issue #19 — bisection plan + diagnostic notes

**Status:** Open. Root cause unknown. Instrumentation shipped (PR #20). Fix not yet attempted.

**Issue URL:** https://github.com/ChrisAdkin8/tf-analyze/issues/19

**Summary (one line):** The GitHub Action engine image `:0.2.5` posts **0** inline `suggestion` comments on `tf-analyze-action-demo` PR #1 where the previous `:0.2.4` image posted **4** on the same diff. Root cause not identified.

---

## Why this matters

The Action's inline `suggestion` blocks are the load-bearing user-facing surface — they're the "click Apply suggestion" fix that newcomers see when they land on the demo PR via the README walkthrough. With v0.2.5 in production, that surface silently does ~half its job. The PR-summary block still renders, so the action isn't visibly broken — it just stops showing the fixable findings inline.

---

## Empirical evidence

### What happened in production

| Run ID | Time (UTC) | Engine ref | Action commit | Inline comments posted | HTML report size |
|---|---|---|---|---|---|
| `25795417175` | 11:10:59 | `v0.2.4` (`544359e`) | v1 → `544359e` | **4** | 60,974 bytes |
| `25796905193` | 11:42:35 | `v0.2.5` (`80504f8`) | v1 → `b654665` (R31.8) | **0** | 37,493 bytes |
| `25819242252` | 18:43:14 | `v0.2.5` | same | **0** | (same shape) |
| `25820197948` | 19:01:29 | `v0.2.5` | same | **0** | (same shape) |

All four `tf-analyze-action-demo` runs were on the demo PR #1, which adds an `aws_s3_bucket "logs"` at lines 128-132 of `terraform/main.tf`. The bucket has 4 attribute-missing findings (`OPS-AWS-TAGS-001`, `ROB-AWS-LIFECYCLE-001`, `ROB-AWS-S3-001`, `SEC-AWS-S3-001`) all correctly anchored at line 130 (the resource declaration line).

### The 4 surviving inline comments on the demo PR

(These are from the 11:10 v0.2.4 run; still visible on https://github.com/ChrisAdkin8/tf-analyze-action-demo/pull/1)

| Comment ID | Rule | Line |
|---|---|---|
| `3233666257` | `OPS-AWS-TAGS-001` | 130 |
| `3233666348` | `ROB-AWS-LIFECYCLE-001` | 130 |
| `3233666405` | `ROB-AWS-S3-001` | 130 |
| `3233666478` | `SEC-AWS-S3-001` | 130 |

### The smoking-gun footer on v0.2.5 runs

The action's PR-summary issue comment ends with:

> *No inline suggestions available for changed files.*

That's the action's signal that `posted = 0`. Per `action.yml` line 413-415, this string is emitted when `posted === 0 && findings.length > 0` — i.e., findings exist but none made it through the inline-suggestion filter.

---

## What's mechanically the same between v0.2.4 and v0.2.5

| File | Diff between `544359e` (v0.2.4) and `80504f8` (v0.2.5) |
|---|---|
| `action.yml` | **0 lines changed.** Verified via `git diff --stat 544359e..b654665 -- action.yml`. |
| `Dockerfile` | **0 lines changed.** Verified via `git diff 544359e..80504f8 -- Dockerfile`. |
| `catalog/` | **0 lines changed.** No rule additions or removals. |
| `scripts/_handlers_*.py` | **0 lines changed.** No rule-firing logic changed. |

So neither the engine's rule-firing path nor the action's posting logic should differ between the two versions. **But the production behavior does.**

## What changed in R31.8 (the only commit between the two tags)

| File | Lines changed | What | Should affect rule firing? |
|---|---|---|---|
| `scripts/_output.py` | +178 | New `_append_compliance_block` function. `_render_pr_summary` becomes a thin wrapper around `_render_pr_summary_impl` with a try/except safety net that returns `_render_pr_summary_minimal_fallback` on exception. | **No** — only affects `--format pr-summary`, not `--format json` (which is what the action reads). |
| `scripts/detect.py` | +2 | Passes `compliance=compliance_report` to two `_render_pr_summary` call sites. | **No** — same reason. |
| `tests/test_pr_summary.py` | +N | 10 new test cases for the new behavior. | N/A (test-only). |
| `CHANGELOG.md` | +M | R31.8 entry. | N/A. |

**There is no plausible mechanism in this diff for the JSON output to change.** And yet the v0.2.5 HTML report has fewer rule IDs in it, and the v0.2.5 action posts 0 where v0.2.4 posts 4. This contradiction is the heart of the bug.

---

## Three hypotheses (ordered by likelihood)

### Hypothesis 1 — `:0.2.5` docker image is built from something other than `80504f8`

**Rationale:** The docker workflow has documented flakiness. R31.7's commit message:

> "Net effect for users since 2026-05-11: `ghcr.io/chrisadkin8/tf-analyze:latest` has been frozen at a pre-R30.13 image. **20+ consecutive failures** because nothing gates the docker workflow's status."

R31.7 (v0.2.4) was the fix. If between v0.2.4 and v0.2.5 the pipeline regressed *again*, the `:0.2.5` registry tag could point at a stale layer (perhaps the pre-R31.7 image, which is also pre-R30.13 — and might fire fewer rules than v0.2.4's image).

**How to verify:**

```sh
docker pull ghcr.io/chrisadkin8/tf-analyze:0.2.5
# Check the engine inside it is R31.8:
docker run --rm --entrypoint cat \
  ghcr.io/chrisadkin8/tf-analyze:0.2.5 \
  /tf-analyze/scripts/_output.py | grep -c _append_compliance_block
# Expected: ≥ 1. If 0, image is pre-R31.8.
```

Also useful:

```sh
# Compare image digest to the docker.yml run that should have built it
gh api repos/ChrisAdkin8/tf-analyze/actions/workflows/docker.yml/runs \
  --jq '.workflow_runs[] | select(.head_sha | startswith("80504f8")) | "\(.id) \(.created_at) \(.conclusion)"'
```

**Estimated probability:** ~55%. The docker pipeline's track record is the strongest signal.

### Hypothesis 2 — R31.8's safety wrapper masks an exception that corrupts JSON output

**Rationale:** R31.8 wrapped `_render_pr_summary` in a try/except that catches *any* exception, writes a `::warning::`, and returns a minimal fallback. If `_render_pr_summary_impl` throws on this specific input, the wrapper would silently emit the fallback PR-summary text — which actually matches the v0.2.5 demo's PR-summary shape (it IS the minimal-fallback structure).

**The contradiction:** The action reads `tf-analyze-findings.json` (`--format json`), NOT the pr-summary file. So even if pr-summary rendering failed, the JSON output would be intact. Unless `detect.py:main` has shared state between the two render paths that gets corrupted on exception.

**How to verify:**

1. Grep the v0.2.5 demo workflow logs for `::warning::` lines from the pr-summary wrapper. If any are present in v0.2.5 runs but not v0.2.4 runs, the wrapper IS firing.
2. Inspect the wrapper's catch block in `scripts/_output.py` (commit `80504f8`). Does it mutate any shared state (e.g., the `findings` list, `summary` dict) before returning the fallback?

**Estimated probability:** ~25%. The mechanism is plausible but the action's JSON read path is supposed to be independent of pr-summary rendering.

### Hypothesis 3 — `--mode auto` resolves differently between the two engine versions

**Rationale:** The action sets `--mode auto` by default, which the engine resolves to `--mode diff` on `pull_request` events. Diff mode filters findings to only those on lines changed in the PR. If diff mode's line-resolution logic changed subtly between v0.2.4 and v0.2.5 (e.g. via a shared helper that was refactored), the same input could produce different filtered output.

**How to verify:** Re-run the demo workflow with `mode: static` explicitly to bypass diff filtering. If 4 inline comments come back → diff mode regression confirmed.

**Estimated probability:** ~15%. R31.8 didn't touch `_diff.py` or the mode-resolution path, but a subtle shared-helper change could have leaked.

### Hypothesis 4 — Catch-all: engine crashed silently and emitted a partial JSON

**Rationale:** If the engine raises an exception before completing finding generation (and `safety_wrapper_kicked_in == True`), the JSON output could be syntactically valid but contain fewer findings than expected. The action would dutifully read it and find nothing to post.

**How to verify:** Look at the size of `tf-analyze-findings.json` in production. PR #20's `debug-upload-findings` toggle makes this trivially inspectable now.

**Estimated probability:** ~5%. Low because the engine has its own error handling that exits non-zero on crash, and the action checks `result.returncode`. But low-probability is not zero-probability.

---

## Step-by-step debug procedure

### Step 1 — Get PR #20's instrumentation into a production run (5 min)

PR #20 (already merged on main) added:
- A `core.info()` log line with per-skip-reason counters
- A `debug-upload-findings` action input (default `'false'`)

Pick ONE of these to get the diagnostics into a real run:

#### Option A (recommended — minimal scope)

Bump the demo workflow to use `@main` instead of `@v1`:

```yaml
# In tf-analyze-action-demo/.github/workflows/tf-analyze.yml
- uses: ChrisAdkin8/tf-analyze@main  # was @v1
  with:
    fail-on: HIGH
    post-pr-comment: true
    compliance-framework: owasp_iac
    attack-graph: true
    ref: latest                     # was v0.2.5
    debug-upload-findings: true     # NEW — opt-in JSON artifact
```

Push an empty commit to `demo-pr-walkthrough`. The run will use the latest `action.yml` (with diagnostics) and the latest `:latest` engine image.

#### Option B (more polished)

Tag `v0.2.6` on `tf-analyze`, let the docker workflow build & publish, move `v1`. Then bump the demo to `ref: v0.2.6` and add `debug-upload-findings: true`. Same diagnostic capture, slower but with a proper version pin.

Recommend **(A)** for the bisection session; once root cause is known, do **(B)** to ship the fix as a tagged release.

### Step 2 — Capture one debug run

```sh
# After triggering:
gh run watch --repo ChrisAdkin8/tf-analyze-action-demo $(gh run list --repo ChrisAdkin8/tf-analyze-action-demo --branch demo-pr-walkthrough --limit 1 --json databaseId --jq '.[0].databaseId')

# When complete, grab the new artifact:
runid=$(gh run list --repo ChrisAdkin8/tf-analyze-action-demo --branch demo-pr-walkthrough --limit 1 --json databaseId --jq '.[0].databaseId')
gh run download --repo ChrisAdkin8/tf-analyze-action-demo $runid -n tf-analyze-findings-json -D /tmp/issue19
ls -la /tmp/issue19/
cat /tmp/issue19/tf-analyze-findings.json | jq '.findings | length, [.[0:3] | map({id, line, fix_hcl_present: (.fix_hcl != null)})]'
```

Also grep the workflow log for the new diagnostic line:

```sh
jobid=$(gh api repos/ChrisAdkin8/tf-analyze-action-demo/actions/runs/$runid/jobs --jq '.jobs[0].id')
gh api repos/ChrisAdkin8/tf-analyze-action-demo/actions/jobs/$jobid/logs \
  | grep -E "tf-analyze inline-suggestion summary"
```

Expected output shape:

```
[tf-analyze inline-suggestion summary] findings=N with_fix_hcl_and_line=M posted=K
  skipped[no_fix_hcl=…,no_line=…,not_in_pr_files=…,not_in_diff_hunk=…,post_failed=…]
  changed_paths=… right_side_lines_files=…
```

### Step 3 — Triage by which counter is non-zero

| Counter ≠ 0 | What it means | Where to dig |
|---|---|---|
| `findings=0` | Engine returned no findings at all | Engine — run locally on the same `terraform/main.tf` and compare |
| `no_fix_hcl` ≈ findings count | Engine emitting findings without `fix_hcl` | Engine — check `_handlers_*.py` and the `fix_hcl` attachment path |
| `no_line` > 0 | Engine emitting findings with `line: null` | Engine — line-resolution path in detection handlers |
| `not_in_pr_files` > 0 | Action's `f.file.replace(/^\/workspace\//, '')` doesn't match `changedPaths` | Action — path normalization regressed |
| `not_in_diff_hunk` > 0 | Engine emits a line that the action's patch-parser doesn't see | Action — `rightSideLines` parser broke, OR engine emits wrong line numbers |
| `post_failed` > 0 | `createReviewComment` 422'd | GitHub permissions / commit SHA mismatch / rate limit |
| All zero, `posted=K` matching | The action works perfectly — issue is closed | (Won't happen — production already shows `posted=0`) |

### Step 4 — Reproduce locally with the latest engine

```sh
mkdir -p /tmp/issue19-repro
curl -s -H "Authorization: token $(gh auth token)" \
  "https://api.github.com/repos/ChrisAdkin8/tf-analyze-action-demo/contents/terraform/main.tf?ref=demo-pr-walkthrough" \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['content']).decode('utf-8'))" \
  > /tmp/issue19-repro/main.tf

# Engine on main:
python3 scripts/detect.py --target /tmp/issue19-repro --format json --mode static 2>/dev/null \
  | jq '[.findings[] | {id, line, resource, fix_hcl_present: (.fix_hcl != null)}]' \
  | head -50
```

Compare to the production artifact JSON. Differences localize the regression to engine-side vs action-side.

**Known-good baseline (from this session's investigation):** the current `main` engine emits 5 findings on lines ≥ 125 (the new bucket), 4 of which have `fix_hcl` set.

### Step 5 — Test each hypothesis

#### Hypothesis 1 (image staleness)

```sh
docker pull ghcr.io/chrisadkin8/tf-analyze:0.2.5
docker run --rm --entrypoint cat ghcr.io/chrisadkin8/tf-analyze:0.2.5 \
  /tf-analyze/scripts/_output.py | grep -c _append_compliance_block
# Expected if image is R31.8: ≥ 1
# If 0: image is pre-R31.8, regression confirmed at the docker pipeline
```

If hypothesis 1 is correct, the fix is:
1. Identify why `docker/metadata-action`'s tag-publish step regressed
2. Re-build & re-push `:0.2.5` (and `:latest`)
3. Bump action consumers to whatever moves the v1 tag forward

#### Hypothesis 2 (safety wrapper)

```sh
runid=<id-of-v0.2.5-run>
jobid=$(gh api repos/ChrisAdkin8/tf-analyze-action-demo/actions/runs/$runid/jobs --jq '.jobs[0].id')
gh api repos/ChrisAdkin8/tf-analyze-action-demo/actions/jobs/$jobid/logs \
  | grep -E "::warning::|tf-analyze-pr-summary safety"
```

If the wrapper IS firing on v0.2.5 runs, look at `_render_pr_summary_impl`'s actual exception path. The wrapper is in `scripts/_output.py` around line 1192 (in v0.2.5 source; check current commit for the exact line).

#### Hypothesis 3 (--mode interaction)

Add `mode: static` to the demo workflow, force re-run. If `posted=4` returns → diff mode is the culprit.

### Step 6 — Fix + regression test + ship

Once root cause is known:

1. **Write the fix.** Likely either:
   - An engine-side fix (e.g., a handler that lost `fix_hcl` attachment, a line-resolver that returns null on a code path R31.8 introduced)
   - A docker-pipeline fix (e.g., metadata-action config that excludes some commits)
   - An action-side fix (less likely given action.yml is unchanged)

2. **Add a regression test.** Depending on where the fix lands:
   - Engine: extend `tests/test_apply_fixes.py` or `tests/test_fixtures.py` to pin the demo PR's fixture
   - Action: extend `tests/test_action_yml.py::TestInlineSuggestionLogging` with a case that mocks the engine output and asserts byLoc size

3. **Open PR, squash-merge.**

4. **Tag a release** (`v0.2.6` or `v0.2.7` depending on what's been tagged in the meantime). Move `v1` to the new tag. Wait for the docker workflow to publish.

5. **Verify on the demo PR.** Push an empty commit, wait for the action run, confirm:
   - `posted=4` in the new diagnostic log line
   - 4 fresh inline `suggestion` comments appear

6. **Close issue #19** with a comment summarizing the actual root cause + linking the fix PR.

---

## Success criteria

- [ ] Demo PR #1 latest action run posts **≥ 4** inline `suggestion` comments
- [ ] Workflow log shows `[tf-analyze inline-suggestion summary] ... posted=4` (or higher)
- [ ] At least one new test pins the regression so it can't reappear silently
- [ ] Issue #19 closed with root cause documented inline
- [ ] Demo workflow can revert to a tagged version pin (`ref: v0.2.X`) instead of `@main` / `:latest`

---

## Estimated effort

**1-2 hours** in a focused session, broken down:

| Step | Time | What |
|---|---|---|
| Step 1-2 | ~20 min | Get instrumentation into a production run + capture |
| Step 3-4 | ~30 min | Triage which counter is non-zero; reproduce locally |
| Step 5 | ~20 min | Verify the hypothesis the counters pointed at |
| Step 6 | ~30 min | Write fix + regression test + ship PR + tag release |
| Verify | ~10 min | Re-run demo + confirm `posted=4` |

---

## Quick reference — important files & commits

| File / Commit | Purpose |
|---|---|
| `action.yml` lines 333-460 | Inline-suggestion JS — the loop that reads findings + posts comments |
| `action.yml` lines 33-46 | The new `debug-upload-findings` input declaration |
| `scripts/_output.py` lines 1192+ | R31.8's compliance block + safety wrapper |
| `scripts/detect.py` lines 2948-2962 | JSON output emission path (the one the action reads) |
| `544359e` | `v0.2.4` engine commit |
| `80504f8` | `v0.2.5` engine commit (R31.8) |
| `b654665` | Current `v1` tag target |
| `a047473` | PR #20 — the diagnostic instrumentation |
| Production runs | `25795417175` (v0.2.4, 4 posts), `25819242252` / `25820197948` (v0.2.5, 0 posts) |

---

## Don't waste time on these

- The 4 inline comments on demo PR #1 dated 2026-05-13T11:11 are **correct, not stale.** They're correctly anchored at line 130 (start of `aws_s3_bucket "logs"`). Don't delete them.
- The empty commit I (a previous Claude session) pushed and reverted at 18:43/19:01 is irrelevant — both runs reproduced the regression, both confirmed `posted=0`.
- Trying to diagnose via `gh run rerun --failed` — that re-runs against the original SHA, so my fixture fix didn't reach the runner. Use `git push --force-with-lease` of a fresh commit instead.

---

## Memo to future-Claude / future-Chris

When you pick this up:
1. Don't repeat the historical excavation. The diff between v0.2.4 and v0.2.5 has been audited (only R31.8 changes, none touching rule firing).
2. The instrumentation is already shipped. Use it. Don't bisect by re-running engines locally without the JSON artifact.
3. The fact that this regression survived shipping to a tagged release means **the test surface didn't cover the integration path**. Whatever the root cause is, ship a test that would have caught it. The session that fixes #19 should leave behind a test that would fail today.
