# tf-analyze

A Claude Code skill for auditing Terraform code. Static + plan-time detection, catalogue-anchored findings, delta tracking, SARIF/HTML/JSON outputs, optional `python-hcl2` heredoc-aware parser. GCP-first; AWS and Azure secondary.

The skill is invoked from Claude Code as `/tf-analyze`. The detection engine (`scripts/detect.py`) is also runnable standalone for CI gating, listing rules, scaffolding new ones, etc. — see [`docs/cli.md`](docs/cli.md).

---

## Capabilities

This is the upfront list — what the skill detects, what outputs it produces, and what it does that the OSS-tool field generally doesn't. If a capability isn't here, it isn't there.

### Detection (catalogue-anchored, ~118 rules)

| Domain | Coverage |
|---|---|
| **Security (`SEC-*`)** | Overly broad IAM (project-level admin roles), public IAM (`allUsers`/`allAuthenticatedUsers`), member-at-both-scopes, sensitive outputs/variable leaks, `data.external` injection risks, hardcoded secrets/API keys/passwords in `.tf`, `.tfvars`, `.auto.tfvars`, and `.tfvars.json`, Azure subscription-scope role assignments, orphan UAMIs (no role_assignment binding), GCS public_access_prevention/UBLA, GCE default-SA + public-IP, Cloud SQL public IPv4, GKE network policy, VPC subnet flow logs (GCP + AWS), Vault `data` source on TF 1.10+ (recommend `ephemeral`), `.tfstate` in repo, world-open SSH (tcp:22) and RDP (tcp:3389), ECR scan-on-push, S3 missing public access block, Cloud Run public ingress, SQS/SNS/ElastiCache missing encryption. |
| **Robustness (`ROB-*`)** | Missing `lifecycle.prevent_destroy` on stateful GCP, AWS, and Azure resources, S3 backend without DynamoDB state locking, `count = X ? 1 : 0` boolean-count pattern, `count`/`for_each` mix, unguarded `[count.index]` references, `for_each` over a `tolist`, unused variables/outputs, deprecated `template_file`, stale `moved` (TF 1.5) and `removed` (TF 1.7) blocks, missing variable validation, `ignore_changes = all`, provider alias mismatches, inconsistent backends, stale remote state, `check` block missing `assert` (TF 1.5+), `precondition` missing `error_message`. |
| **Stack (`STK-*`)** | GKE: missing Workload Identity, private nodes, secrets encryption, master authorized networks, node-pool secure-boot/integrity-monitoring. GCS: missing versioning, logging-target leak. KMS: missing rotation period, key/keyring location parity. CloudSQL: deprecated attributes, missing backups, missing deletion protection, no SSL enforcement, EOL engine version. DNSSEC. BigQuery: missing CMEK. Azure NSG missing flow log resource. |
| **Operational (`OPS-*`, `STYLE-*`, `MOD-*`, `COST-*`, `CI-TEST-*`)** | Missing labels/tags on GCP, AWS, and Azure resources, prod-scoped deletion protection, missing variable descriptions, unpinned modules, expensive resources without cost controls (GCP + AWS), modules without `*.tftest.hcl`. CloudWatch log groups without retention, ASGs without max_size. |
| **Cross-resource (`graph_check`)** | Cluster→all-node-pools assertions, KMS key-ring↔consumer location parity, IAM project+resource breadth, GCS logging-target hardening. New graph functions register in `_GRAPH_CHECKS` in `detect.py`. |
| **CIS mapping** | Findings carry the relevant CIS GCP Foundations Benchmark v4.0 control where one applies (1.6, 5.1, 6.6.7, 8.5.2, etc.) for compliance reporting. |

`python3 scripts/detect.py --list-rules` enumerates everything; `--explain RULE-ID` prints the full entry for one.

### Execution modes

| Mode | Cost | What it does |
|---|---|---|
| `static` (default) | ~5 min | Full report against the source HCL — no credentials needed. |
| `diff` | ~1 min | Per-file scan restricted to `.tf` files changed since `<diff-base>` (auto-detected `main`/`master`). Right for PR CI. |
| `plan` | ~15 min | Static + plan-time re-evaluation of `resource_arg`/`resource_missing_arg`/`resource_present`/`hcl_attr`/`data_source_present` rules against `terraform show -json` resolved values. Catches violations that only appear after variable resolution. |
| `verify-fixed` | ~1 min | Reads a prior report and re-probes each finding's location — `FIXED` / `STILL PRESENT` / `MOVED`. Useful for asserting a fix landed before closing the ticket. |
| `self-test` | ~2 min | Walks `fixtures/` against the catalogue. Run before committing skill changes. |

### Output formats

- `markdown` (default) — full report with executive summary, finding density by file, action plan, suppressed findings section.
- `json` — machine-readable findings list. Used by `--compare` and CI integrations.
- `sarif` — SARIF v2.1.0 with `helpUri`, `partialFingerprints`, `security-severity` (9.5/7.5/5.0/3.0/1.0), CIS tags. GitHub Code Scanning renders these as line-level annotations on the PR diff. Schema documented in `SKILL.md`.
- `html` — self-contained report with inline CSS, urgency-coloured badges, collapsible per-rule details. Right for sharing with non-CLI reviewers.

### Differentiators (vs tfsec / Checkov / KICS / tflint)

1. **Recommendation verification.** Every recommendation can be validated by writing the proposed HCL into a sentinel `terraform init`-ed tempdir and running `terraform validate`. No other scanner self-checks its own fix suggestions.
2. **Delta tracking.** Each finding has a stable `(catalogue_id, file, resource)` join key. Reports compare against the previous run and surface `Resolved` / `New` / `Unchanged`. tfsec/Checkov re-emit the full set every run with no longitudinal memory.
3. **Suppression with expiry.** `.tf-analyze-ignore.yaml` entries take an `expires:` field. Expired suppressions don't silently re-surface as "new" findings — they're tagged `was_suppressed_until: <date>` so the report explicitly shows them.
4. **CLAUDE.md convention verification.** Step 11 of the LLM-judgement pass reads project-local docs and verifies code matches stated rules ("PKI TTLs: leaf 72h", "no default credentials"). No OSS scanner reads project docs.
5. **Provider/Terraform version dispatch.** Catalogue entries can declare `applies_when: { min_terraform: "1.10" }` or `min_provider: { google: "5.0" }`. Rules silently skip when the target's `required_version` / `required_providers` constraint can't reach the minimum.
6. **Cross-resource (graph) detector kind.** `pattern_kind: graph_check` invokes a registered Python function with a resource index — used for "all node pools must X", logging-target hardening, IAM breadth, KMS location parity. The scaffolding generalises; new graph rules are ~30 LoC each.
7. **`scripts/detect.py --new-rule RULE-ID`** scaffolds catalogue YAML + fixture skeleton + self-test stub. Authoring a new rule is `--new-rule SEC-FOO-007` then editing the TODOs.
8. **Optional `python-hcl2` fast-path** for heredoc-aware attribute extraction. Default install is stdlib-only; `--use-hcl2` (or `TF_ANALYZE_USE_HCL2=1`) opts in when `python-hcl2` is installed. Off by default to keep the install zero-pip-deps.

---

## Quickstart

```sh
# Install (symlinks the repo into ~/.claude/skills/tf-analyze)
git clone <this-repo> ~/Projects/tf-analyze
cd ~/Projects/tf-analyze
./install.sh

# In Claude Code:
/tf-analyze                                    # full audit, all areas
/tf-analyze focus:security mode:diff           # PR review
/tf-analyze mode:verify-fixed                  # confirm prior fixes

# Standalone (no Claude Code):
python3 scripts/detect.py --target /path/to/tf
python3 scripts/detect.py --target . --mode diff --fail-on HIGH --format sarif > out.sarif
python3 scripts/detect.py --list-rules
python3 scripts/detect.py --explain SEC-GCP-IAM-001
python3 scripts/detect.py --new-rule SEC-FOO-007

# Try the demo corpus:
python3 scripts/detect.py --target examples/terragoat
```

---

## Repository layout

```
.
├── SKILL.md                # Skill prose — invoked by Claude Code as /tf-analyze
├── README.md               # This file
├── install.sh              # Wires the repo into ~/.claude/skills/tf-analyze
├── catalog/                # ~118 rule definitions (one YAML per rule)
│   └── README.md           # Schema reference
├── fixtures/               # Single-rule isolation tests, used by self_test
├── examples/
│   └── terragoat/          # Multi-file deliberately-vulnerable demo corpus
├── scripts/
│   ├── detect.py           # Detection engine (~2400 LoC, stdlib only)
│   ├── self_test.py        # Walks fixtures/ vs catalog/, asserts expected IDs
│   ├── test_schema.py      # Catalogue schema validator regression test
│   ├── stub-status.py      # Reports stale `status: stub` entries by age
│   └── gen-cli-docs.py     # Regenerates docs/cli.md from argparse
├── docs/
│   └── cli.md              # Auto-generated CLI reference for detect.py
├── integrations/           # Pre-commit + GitHub Actions configs
└── reports/                # Example report outputs (delta-tracking demos)
```

The skill files (`SKILL.md`, `catalog/`, `scripts/`, `fixtures/`, `integrations/`) are at the repo root so `./install.sh` can `ln -s` the whole directory into `~/.claude/skills/tf-analyze` — no nested `skill/` subdir.

---

## Demo corpus — `examples/terragoat/`

A three-cloud intentionally-vulnerable Terraform corpus (GCP, AWS, Azure) organised by OWASP Top 10, modelled on Bridgecrew's [`terragoat`](https://github.com/bridgecrewio/terragoat). 30 files across the three clouds trigger 192 findings against the current rule set, covering SEC, ROB, STK, OPS, and COST rules for all three providers.

It serves three jobs:

1. **Smoke test for the engine.** `python3 scripts/detect.py --target examples/terragoat --format json | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['findings']))"` should equal **192**. Drift in this number is a regression signal.
2. **Calibration target for new rules.** When you write a new detector, add a triggering snippet to the relevant `examples/terragoat/*.tf` file and re-run — your new ID should appear alongside the existing ones with no spurious cross-talk.
3. **Live demo for first-time users.** Reports against this corpus are realistic-shaped (multi-file, GCP+Azure+Vault, real cross-resource interactions) rather than the isolated single-rule fixtures under `fixtures/`.

See [`examples/terragoat/README.md`](examples/terragoat/README.md) for the rule-by-rule breakdown.

### Why both `fixtures/` and `examples/terragoat/`?

- **`fixtures/`** are minimal, one-rule-per-directory inputs used by `self_test.py`. A failing self-test points at exactly which rule broke.
- **`examples/terragoat/`** is a representative *project* exercising rules in combination — including `graph_check` rules that need ≥2 resources to fire and corpus-level rules (`CI-TEST-001`) that need a directory not a file.

Isolated fixtures alone miss interaction bugs; a project-shaped corpus alone loses diagnostic precision. Both serve.

---

## Adding a rule

```sh
python3 scripts/detect.py --new-rule SEC-MYDOMAIN-001
# wrote catalog/SEC-MYDOMAIN-001.yaml
# wrote fixtures/sec_mydomain_001/main.tf
```

Edit the two scaffolded files (TODOs marked clearly), then:

```sh
python3 scripts/self_test.py             # regression test
python3 scripts/detect.py --explain SEC-MYDOMAIN-001
python3 scripts/detect.py --strict-catalog --target /tmp # validates schema
```

Schema reference at [`catalog/README.md`](catalog/README.md). Pattern kinds: `grep`, `resource_arg`, `resource_missing_arg`, `resource_present`, `hcl_attr`, `data_source_present`, `resource_body_contains`, `firewall_open_port`, `moved_block_present`, `removed_block_present`, `check_block_missing_assert`, `precondition_missing_error_message`, `graph_check`, plus the corpus-level kinds (`cross_module`, `output_sensitive_leak`, `templatefile_sensitive_leak`, etc.). For cross-resource rules, register a Python function in `_GRAPH_CHECKS` and reference it from the catalogue YAML via `kind: graph_check, function: <name>`.

---

## CI integration

The skill ships with two ready-to-use configs under `integrations/`:

- **`integrations/pre-commit-hook.yaml`** — diff-mode hook (~<2s on a 5k-file repo). Resolves the skill via `$TF_ANALYZE_SKILL_ROOT` with a fallback to the install path, so non-standard install locations work.
- **`integrations/github-action.yml`** — full Actions workflow with SARIF upload to Code Scanning + HTML artefact. PR runs are diff-mode + fail-on-HIGH; pushes to main are full static scans.

The repo's own CI (`.github/workflows/ci.yml`) gates the skill itself: `self_test.py`, `test_schema.py`, `gen-cli-docs.py --check`, `stub-status.py --age 180d`. See `integrations/README.md` for adapting to GitLab / CircleCI / Buildkite (single-line `python3` invocation works anywhere).

---

## Maintenance

- `python3 scripts/stub-status.py --age 90d` — find stubs older than 90 days. Stubs are catalogue entries with `status: stub`; they're excluded from scans by default and indicate a half-finished rule. The CI gate runs at `--age 180d` (warns earlier than half a year is over-zealous).
- `python3 scripts/gen-cli-docs.py` — regenerate `docs/cli.md` after any argparse change. CI runs `--check` and fails if the docs are stale.
- `python3 scripts/test_schema.py` — synthetic broken-YAML regression test for the catalogue validator. Add a new case here when extending the schema.

---

## Provenance

This skill was built and refined inside the [`consul-mcp-agents`](https://github.com/example/consul-mcp-agents) project — an HCP Vault + Consul + GKE stack. Many catalogue rules trace to incidents and audit findings on that infra. The skill is provider-agnostic in design and exercised against the GCP + HashiCorp + Azure providers; AWS coverage is intentionally lighter (3 SEC rules) as a reflection of the original use case.
