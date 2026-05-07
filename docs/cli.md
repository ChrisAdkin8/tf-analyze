# `detect.py` CLI reference

**Auto-generated** by `scripts/gen-cli-docs.py` from `scripts/detect.py`'s argparse. Do not edit by hand — re-run the generator after changing flags.

## Scan target

### `--target DIR`

Directory to scan. May be specified multiple times for fleet mode.

### `--catalog CATALOG`

**Default:** `<skill>/catalog`

Catalog directory


## Output

### `--format FORMAT`

**Choices:** `text`, `json`, `sarif`, `html`, `compliance`

**Default:** `text`

### `--reports-dir REPORTS_DIR`

Reports directory (default: <skill>/reports). Used for auto-discovery in --compare and --mode verify-fixed.


## Mode

### `--mode MODE`

**Choices:** `static`, `diff`, `verify-fixed`, `fleet`, `trend`, `pr-review`

**Default:** `static`

Execution mode. fleet: multi-repo scan. trend: risk trajectory over git history.

### `--prior-report PRIOR_REPORT`

Markdown report to verify (for --mode verify-fixed). If omitted, picks the most recent tf-analysis-*.md under reports/.

### `--diff-base DIFF_BASE`

Git ref to diff against (e.g., main). Only scan changed .tf files.

### `--plan-json PATH`

Path to `terraform show -json plan.tfplan` output. When supplied, the catalogue's resource_arg / resource_missing_arg / resource_present / hcl_attr / data_source_present rules are re-evaluated against resolved values from the plan. Static findings still run; plan findings are tagged with mode='plan' so the report can disambiguate. Required for catching variable-resolved violations (e.g. tfvars setting an IAM role to a forbidden value).


## Filtering

### `--only-fixture ONLY_FIXTURE`

Restrict catalogue to entries listing this fixture name

### `--include-stubs`

Include catalogue entries with status: stub

### `--strict-catalog`

Abort with exit code 2 on any catalogue schema error. Default behaviour is loud-warn-and-skip: print ERROR lines to stderr and continue with the entries that did parse.

### `--focus FOCUS`

Restrict --list-rules / scans to entries in this section (security, robustness, dry, style, simplicity, ops, cicd, module, stack, verification).


## Suppression

### `--no-suppress`

Disable all suppression (show every finding). Default: suppressions from .tf-analyze-ignore.yaml + inline `# tf-analyze:ignore <ID>` comments are applied.


## Comparison & gating

### `--compare COMPARE`

Path to a prior JSON report to compare against (outputs delta)

### `--auto-compare`

Auto-discover most recent prior JSON report and compute delta.

### `--fail-on FAIL_ON`

**Choices:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

Exit with code 1 if any finding at this urgency or above exists


## Auto-stub

### `--auto-stub AUTO_STUB`

Directory to write auto-generated catalogue stubs. Combined with --propose-stub IDs or with findings whose IDs are novel (not in catalog).

### `--propose-stub PROPOSE_STUB`

Comma-separated list of exploratory IDs to scaffold as stubs. Used by the judgement pass to promote novel findings. Requires --auto-stub <dir>.


## Optional fast-path

### `--use-hcl2`

Enable optional python-hcl2 fast-path for heredoc-aware attribute extraction. Requires `pip install python-hcl2` — if the dependency is missing this flag is a no-op and the regex path is used. Off by default to honor the stdlib-only promise; can also be enabled via TF_ANALYZE_USE_HCL2=1.


## Meta-commands

### `--list-rules`

Print every catalogue ID with title and urgency, grouped by domain. Honors --focus, --include-stubs. No scan is run.

### `--explain RULE-ID`

Print the full catalogue entry for the given rule ID and exit. No scan is run.

### `--new-rule RULE-ID`

Scaffold a new catalogue entry and fixture skeleton for the given ID (must match DOMAIN-SUBDOMAIN-NNN format). Writes catalog/<ID>.yaml and fixtures/<slug>/main.tf with TODO markers, then exits.


## Other

### `-h/--help`

show this help message and exit

### `--targets-file`

File containing one target directory path per line (for --mode fleet).

### `--attack-graph`

Build a directed attack-path graph from internet-reachable resources to crown jewels (RDS, KMS keys, Secrets Manager, S3/GCS buckets). With --format html adds an interactive Attack Graph tab (force-directed SVG, drag, click-to-inspect, critical path highlighted in red). With --format text (default) appends a Mermaid flowchart block after findings. Also enables adversarial scenario narratives for HIGH/CRITICAL findings.

### `--repo`

GitHub repository (owner/repo) for --mode pr-review.

### `--pr-number`

GitHub pull request number for --mode pr-review.

### `--compliance`

Add a CIS compliance gap report tab to HTML output, or (with --format compliance) output a plain-text compliance table. Maps findings against CIS AWS/GCP/Azure benchmark controls defined in catalogue cis: fields.

### `--oscal`

Write an OSCAL Assessment Results JSON file to PATH. Requires --compliance. Compatible with any --format.

### `--gen-tests`

Generate .tftest.hcl assertion files for each finding whose catalogue entry defines a `test_template` field. Files are written to OUTDIR (created if absent). Native Terraform test format (requires Terraform >= 1.6).

### `--show-fixes`

When a catalogue entry carries a `fix_hcl` snippet, render it alongside each finding. HTML: syntax-highlighted block inside the finding detail. Text: indented snippet below the finding line.

### `--output`

Write report output to PATH instead of stdout. The file is created or overwritten. stderr (progress, counts, errors) is unaffected.

### `--lookback`

Days of git history to analyse in --mode trend (default: 30).

