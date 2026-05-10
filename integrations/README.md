# tf-analyze integrations

Drop-in configs for running `detect.py` in pre-commit, GitHub Actions, and other CI systems.

## Pre-commit hook

Local fast-feedback — runs on every `git commit` against changed `.tf` files.

**Install:** merge the `hooks:` entry from `pre-commit-hook.yaml` into your `.pre-commit-config.yaml` under a `repo: local` block. The file ships as a single hook definition (not a full config), so it nests cleanly under any existing `repos:` list.

**Skill path resolution:** the hook reads `$TF_ANALYZE_SKILL_ROOT` and falls back to `$HOME/.claude/skills/tf-analyze` (the standard Claude Code location). If you've cloned the skill elsewhere, export the variable in your shell rc file or pass it via a CI secret:

```sh
export TF_ANALYZE_SKILL_ROOT=/opt/skills/tf-analyze
```

The fallback path is silently used if the env var is unset, which is the right behaviour for the common case but can mask a missing install — the hook will fail with a Python `FileNotFoundError` rather than a "tf-analyze didn't run" silent pass, so failures are visible.

**Behavior:** diff mode only scans changed files. `--fail-on HIGH` blocks commits with HIGH or CRITICAL findings.

**Tuning:**

- Too strict? Raise to `--fail-on CRITICAL`.
- Too slow? Add `--only-fixture` exclusions or run on a `.tf` file subset via pre-commit's `files:` regex.
- Need to bypass once? `git commit --no-verify` (but do NOT make this the norm — fix the finding).

## GitHub Actions

Full CI integration with SARIF upload to Code Scanning and an HTML artifact for manual review.

**Install:** copy `github-action.yml` into `.github/workflows/tf-analyze.yml`.

**Behavior:**

- **PR runs:** diff mode — only changed files scanned. Fails the job on HIGH+ findings.
- **Main/master push:** full static scan. Always uploads SARIF + HTML report.
- **SARIF upload:** findings appear in the repo's Security → Code Scanning tab, with line-level annotations on the PR diff.

**Prerequisites:**

- `security-events: write` permission (already in the workflow).
- Public repo OR Advanced Security enabled (for Code Scanning uploads).
- Python 3.12 on the runner (stdlib only — no pip install needed).

## Verify-fixed workflow

After addressing findings from a prior report, run:

```bash
python3 ~/.tf-analyze/scripts/detect.py \
  --target . \
  --mode verify-fixed \
  --prior-report reports/tf-analysis-2026-04-01.md
```

This parses the prior report, re-probes each finding's location, and writes a new markdown report showing: `FIXED`, `STILL PRESENT`, or `MOVED`. Useful for audit trails and for asserting fixes landed before deleting the follow-up ticket.

## Score badge service

A small FastAPI app under [`badge-service/`](badge-service/) that returns embeddable SVG badges of a repo's most recent `tf-analyze` score. Each rendered badge is an ad — score + grade are inherently shareable, and the badge is a thin renderer on top of stored scan results.

**Endpoints:**

| Route | What it returns |
|---|---|
| `GET /score/<owner>/<repo>.svg` | Badge for the `main` branch — `tf-analyze: 82 (B)` shields.io-shape SVG, coloured by grade. |
| `GET /score/<owner>/<repo>/<branch>.svg` | Branch-specific badge. Branches with `/` in the name (`release/v1.0`, `feat/foo`) round-trip cleanly. |
| `GET /health` | Liveness check for Fly.io. |
| `POST /ingest` | Upload a scan result. HMAC-SHA256-signed body authenticated against `TFA_BADGE_INGEST_SECRET`. Body is `{owner, repo, branch, scan: <detect.py --format json output>}`. |

**Embed in any README:**

```md
![tf-analyze](https://tf-analyze-badge.fly.dev/score/owner/repo.svg)
```

**Wire into CI** with the bundled `scripts/upload-score.sh` — POSTs the engine's JSON output to `/ingest` after every push to main:

```sh
TFA_BADGE_INGEST_SECRET=$BADGE_SECRET \
TFA_BADGE_URL=https://tf-analyze-badge.fly.dev \
  ./integrations/badge-service/scripts/upload-score.sh \
  ChrisAdkin8 tf-analyze main scan.json
```

**Deploy** to Fly.io (operator step — engineering only ships the code):

```sh
cd integrations/badge-service
flyctl launch --copy-config --no-deploy
flyctl secrets set TFA_BADGE_INGEST_SECRET=$(openssl rand -hex 32)
flyctl deploy
```

The default backend is an in-memory store; persistence on redeploy requires swapping `InMemoryStore` for a Redis-backed implementation (the hook is in place; production deployment would supply it).

## MCP server (Model Context Protocol)

Wrapper at [`mcp-server/`](mcp-server/) that exposes the engine over MCP — the standard tool-protocol used by Claude Desktop, Cursor, Continue.dev, Cline, the JetBrains AI Assistant, and the wave of MCP-aware shells.

**Tools exposed:**

| Tool | Description |
|---|---|
| `scan_workspace(path, mode, show_info, attack_graph)` | Run a tf-analyze scan; returns the engine's `summary` + `findings`. |
| `explain_rule(rule_id)` | Catalogue entry for one rule. ID validated against `^[A-Z][A-Z0-9-]{2,63}$` before the engine sees it. |
| `apply_fixes(path, dry_run=True)` | Preview or apply `--apply-fixes`. Default dry-run so the agent must opt in to writes. |
| `attack_graph(path)` | Build the graph; returns JSON shape + a Mermaid string. |
| `compliance_report(path, framework='cis')` | Plain-text compliance gap report. Frameworks: `cis`, `pci_dss`, `soc2`, `owasp_iac`, `all`. The `owasp_iac` framework maps against the [OWASP IaC Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) — static-analysable items only. |

The catalogue index is also exposed as the resource `tfanalyze://catalogue`.

**Wire into Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "tf-analyze": {
      "command": "python3",
      "args": ["/path/to/tf-analyze/integrations/mcp-server/server.py"]
    }
  }
}
```

Cursor (`~/.cursor/mcp.json`) and Continue.dev share the same shape. **Health check:** `python3 server.py --health` confirms the engine wiring.

**Why MCP:** the `/tf-analyze` Claude Code skill is Claude-specific. MCP standardises the tool-shape so the engine becomes addressable from every other AI agent surface — without per-host adapters.

**Hardening (Round 30 Phase 0):** the server treats every tool call as an interaction with a possibly-adversarial agent.

| Risk (OWASP LLM Top 10) | Defence |
|---|---|
| **LLM06** — excessive agency | `_resolve_target` enforces containment under `TFA_REPO_ROOT`; symlinks at the workspace root are rejected. `TFA_MCP_ALLOW_OUTSIDE_ROOT=1` enables the legitimate sibling-repo workflow. |
| **LLM01/05** — prompt injection / output handling | Every tool wraps its output. Dict tools (`scan_workspace`, `attack_graph`) carry `_envelope: tf-analyze-output` / `_treat_as: data` / `_kind: <…>` metadata; string tools wrap in `<tf-analyze-output kind="…">…</tf-analyze-output>` plus a "treat as data" preamble. A finding's title or recommendation arrives at the agent visibly inside the envelope, not above it. |
| **LLM10** — unbounded consumption | `MAX_FINDINGS_RETURNED` (default 500, env `TFA_MCP_MAX_FINDINGS`) caps `scan_workspace`'s findings list; `MAX_OUTPUT_BYTES` (default 1 MB, env `TFA_MCP_MAX_OUTPUT_BYTES`) byte-truncates string-tool output. Truncation is signalled to the agent (`_truncated: true` / inline marker). |

Subprocess timeouts read at call-time from env so ops can dial them without code edits: `TFA_MCP_TIMEOUT` (default 120s), `TFA_MCP_APPLY_TIMEOUT` (default 300s). Full env-var matrix in [`mcp-server/README.md#hardening`](mcp-server/README.md#hardening). Test coverage in `tests/test_mcp_server_hardening.py` (22 cases).

## Terraform provider

Native Terraform provider under [`../terraform-provider/`](../terraform-provider/) (Go, `terraform-plugin-framework`). The headline use case: gate `terraform apply` on a clean tf-analyze scan **without external CI infrastructure** by running the engine at plan time.

```hcl
data "tfanalyze_scan" "this" {
  target       = path.module
  attack_graph = true
}

resource "null_resource" "gate" {
  lifecycle {
    precondition {
      condition     = data.tfanalyze_scan.this.high_count == 0
      error_message = "tf-analyze: HIGH findings — fix before applying."
    }
  }
}
```

Computed outputs: `score`, `grade`, `scoring_version`, per-tier `*_count`, `findings_json`, `json_report`. v1 is data-source-only; `tfanalyze_gate` and `tfanalyze_apply_fixes` resource shapes are on the roadmap.

**Build from source:**

```sh
cd terraform-provider
go build -o terraform-provider-tfanalyze
```

See [`terraform-provider/README.md`](../terraform-provider/README.md) for the full configuration reference, `dev_overrides` setup, and roadmap.

## HCP Terraform Run Task

Pre-apply gate that scans Terraform Cloud / HCP Terraform plans before they run. See [`run-task/`](run-task/) for the FastAPI server, `Dockerfile`, and the deployment notes in [`docs/run-task.md`](../docs/run-task.md). HMAC-SHA512 signature verification on every callback; rejects bodies whose signature doesn't match the registered secret.

## Other CI systems

The core invocation is just a single `python3` call with stdlib-only dependencies, so adapting to GitLab CI, CircleCI, Buildkite, etc. is trivial:

```bash
python3 scripts/detect.py --target . --mode diff --format sarif --fail-on HIGH
```

Exit code `0` = clean; exit `1` = findings at or above `--fail-on`; exit `2` = configuration error.
