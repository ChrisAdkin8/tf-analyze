## The GitHub Action's gate fails when the scan says it should

- **`--attack-graph` keeps a leaked secret's urgency**: a finding on a
  network resource the graph found unreachable still drops one tier, but
  a credential-exposure rule (CWE-798, CWE-259, CWE-256, CWE-312,
  CWE-321, CWE-522 or ATT&CK T1552) no longer does. A hard-coded
  database password was CRITICAL without the flag and HIGH with it, so
  the Action (which turns the flag on by default) passed
  `fail-on: CRITICAL`.
- **`mode: fleet`**: fleet JSON has findings under `by_target`, not
  `findings`, so the Action's gate saw none and passed; and only an
  escalated fleet finding carried an `urgency`. Fleet findings now carry
  urgency, title and the other report fields, and the gate reads them.
  It also fails on a fleet's unreadable files and timed-out rule checks
  (now in the fleet JSON as `rule_timeouts`). `--mode fleet
  --format sarif` emitted the Markdown report; it now emits SARIF.
- **`mode: trend`** is refused by the Action with a reason: it is a
  history table with no findings to gate, and the gate crashed on it.
- **`mode: plan`** was accepted by the Action but isn't an engine mode,
  so every run failed. It is now a static scan of the new `plan-json`
  input (passed as `--plan-json`, and usable with the other modes too).
- **`section`** was passed as `--section`, which the engine doesn't
  accept (it is `--focus`), so any run with `section:` set failed. The
  same fix applies to the `integrations/github-action.yml` template and
  the pre-commit docs. A test now parses the flags the Action passes
  with the engine's own argument parser.
- **Baseline on PRs**: the `baseline:` report was read from the PR's
  checkout, so a PR could add its own findings to it. On pull requests
  and merge-queue runs it is now read from the base branch, like the
  config (unless `trust-pr-config: true`); if the base branch has none,
  the scan runs without a baseline. A baseline entry with no `urgency`
  (an older report) counts as its rule's default urgency, so it can't
  hide a finding that was escalated above it; it used to match any
  urgency.
- **Report files**: the Action wrote its reports and the engine's stderr
  into the workspace, which is the PR's checkout, so a committed symlink
  named `tf-analyze.sarif` (or any other report name) sent the write
  wherever it pointed. They now go to a fresh `mktemp -d` folder under
  `$RUNNER_TEMP`. **If a workflow read
  `${{ github.workspace }}/tf-analyze-findings.json`, use the
  `json-report-path` output instead** (likewise `sarif-report-path`
  and `html-report-path`).
