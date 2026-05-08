# tf-analyze Implementation Plan

Eight items in recommended implementation order. Each section contains:
exact files to create or modify, the implementation approach with
specific function signatures and code structure, acceptance criteria,
and how each item enables the next.

---

## §1 VS Code Extension — Attack Graph Webview + Marketplace Publication

### Why first
The extension is already scaffolded and compilable. Publishing takes 30 minutes and
returns passive installs indefinitely. The attack graph webview is the screenshot-worthy
feature that makes the extension worth sharing — it is visually unique among all
Terraform tooling.

### Files to create
```
vscode-extension/assets/icon.png          128×128 PNG (tf-analyze shield logo)
vscode-extension/src/attackGraph.ts       new — webview provider
vscode-extension/media/attack-graph.js    new — d3.js bundle (self-contained)
vscode-extension/media/attack-graph.css   new — graph styles
```

### Files to modify
```
vscode-extension/src/extension.ts         wire attackGraph command + provider
vscode-extension/package.json             add command, webview contributes, bump version
vscode-extension/README.md (in ext dir)   add screenshot placeholder + Marketplace description
```

### Implementation: `attackGraph.ts`

```typescript
// The webview queries detect.py once, caches, re-renders on panel show.
export class AttackGraphPanel {
  static currentPanel: AttackGraphPanel | undefined;
  private readonly _panel: vscode.WebviewPanel;

  static createOrShow(context: vscode.ExtensionContext, findings: Finding[]): void {
    const col = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
    if (AttackGraphPanel.currentPanel) {
      AttackGraphPanel.currentPanel._panel.reveal(col);
      AttackGraphPanel.currentPanel._update(findings);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      "tfAnalyzeAttackGraph",
      "tf-analyze: Attack Graph",
      col,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    AttackGraphPanel.currentPanel = new AttackGraphPanel(panel, context, findings);
  }

  private _update(findings: Finding[]): void {
    // Run detect.py --attack-graph --format json, parse graph section
    // Post message to webview: { type: "graph", nodes: [...], edges: [...] }
  }

  private _getHtmlForWebview(): string {
    // Inline d3.js + attack-graph.js; no external CDN calls
    // Graph layout: force-directed, urgency-coloured nodes
    // Crown jewels: double border; internet-reachable: pulsing glow
    // Click node: show resource type, finding IDs, urgency in sidebar
    // Export button: download SVG
  }
}
```

The JSON output from `detect.py --attack-graph --format json` already contains an
`attack_graph` key with `nodes` and `edges`. Parse it directly; no additional flag needed.

Node colouring scheme (matches existing HTML report):
- `compute` → `#4A90D9` (blue)
- `storage` → `#E8A838` (amber)
- `iam` → `#D4A017` (gold)
- `network` → `#7B9EA6` (slate)
- `key` / `secret` → `#6BBF84` (green)
- `unknown` → `#888`

Crown jewels: radius 16 (vs 10 for normal nodes), double ring.
Internet-reachable: `stroke-dasharray: 5,3` animated border.
Critical-path edges: `stroke: #E53E3E; stroke-width: 2.5`.

### Implementation: `package.json` additions

```json
"commands": [
  { "command": "tf-analyze.showAttackGraph",
    "title": "tf-analyze: Show Attack Graph",
    "icon": "$(type-hierarchy)" }
],
"menus": {
  "view/title": [
    { "command": "tf-analyze.showAttackGraph",
      "when": "view == tfAnalyzeFindings", "group": "navigation" }
  ]
}
```

### Publishing steps (manual, one-time)
1. `npm install -g @vscode/vsce`
2. Create publisher at `marketplace.visualstudio.com/manage`
3. Generate PAT with Marketplace scope
4. `vsce login hashicorp`
5. `cd vscode-extension && npm run package` — verify `.vsix` size < 2MB
6. `vsce publish` — confirm listing appears at marketplace

### Acceptance criteria
- [ ] `npm run compile` exits 0 with no TypeScript errors
- [ ] `npm run package` produces `tf-analyze-0.1.0.vsix`
- [ ] Pressing F5 in VS Code launches Extension Development Host; attack graph panel opens on a `.tf` file with `aws_instance` and `aws_s3_bucket`
- [ ] Nodes are coloured by type; crown jewel node (e.g. `aws_s3_bucket`) has double ring
- [ ] Clicking a node shows resource address and any finding IDs in the sidebar panel
- [ ] Extension is listed on Marketplace; `code --install-extension hashicorp.tf-analyze` succeeds
- [ ] Install badge renders in `README.md`

---

## §2 Docker Image + GHCR Publication Pipeline

### Why second
Zero-friction adoption. Every CI system has Docker. This removes Python as an install
requirement and makes the tool runnable in one line by anyone.

### Files to create
```
Dockerfile                              repo root
.github/workflows/docker.yml            build + push workflow
```

### Files to modify
```
README.md                               add Quick Start docker one-liner
docs/cli.md                             add docker section
```

### `Dockerfile`

```dockerfile
FROM python:3.12-slim AS base

WORKDIR /tf-analyze

# Copy only what detect.py needs at runtime
COPY scripts/detect.py .
COPY catalog/ ./catalog/

# Verify the tool starts (catches catalogue schema errors early)
RUN python3 detect.py --list-rules --catalog ./catalog/ > /dev/null

# Run as non-root
RUN useradd -r -u 1001 tfanalyze
USER tfanalyze

ENTRYPOINT ["python3", "/tf-analyze/detect.py", "--catalog", "/tf-analyze/catalog/"]
```

The `--catalog` default in `detect.py` is resolved relative to `__file__`, so it works
automatically when the script lives at `/tf-analyze/detect.py`.

### `.github/workflows/docker.yml`

```yaml
name: docker
on:
  push:
    branches: [main]
    tags: ['v*.*.*']

jobs:
  build-push:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-qemu-action@v3        # for arm64
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/chrisadkin8/tf-analyze
          tags: |
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=raw,value=latest,enable=${{ github.ref == 'refs/heads/main' }}
      - uses: docker/build-push-action@v5
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

### `README.md` Quick Start section

Add immediately after the existing install block:

```markdown
### Docker (no Python required)
docker run --rm -v $(pwd):/workspace \
  ghcr.io/chrisadkin8/tf-analyze \
  --target /workspace --format html > report.html
```

### Acceptance criteria
- [ ] `docker build -t tf-analyze-local .` completes in < 60s
- [ ] `docker run --rm tf-analyze-local --list-rules` prints all 194 rules
- [ ] `docker run --rm -v ./fixtures/aws_rds_eol_version:/workspace tf-analyze-local --target /workspace --format json` produces valid JSON with `STK-AWS-RDS-004` finding
- [ ] GitHub Actions workflow builds and pushes on `main` commit; `ghcr.io/chrisadkin8/tf-analyze:latest` is pullable
- [ ] Multi-arch: `docker manifest inspect ghcr.io/chrisadkin8/tf-analyze:latest` shows both `amd64` and `arm64` digests

---

## §3 GitHub Action — PR Suggestion Blocks

### Why third
The Action already posts PR comments. Reformatting to GitHub suggestion blocks turns
every finding with `fix_hcl` into a 1-click fix. This is the highest per-finding
virality moment — the fix appears in the PR diff view where the whole team sees it.

### How GitHub suggestion blocks work
A suggestion block is a PR **review comment** (not an issue comment) posted against a
specific file + line in the diff. GitHub renders it as a green diff with an
"Apply suggestion" button. The comment body must be:

````
```suggestion
<replacement line(s)>
```
````

The replacement replaces the exact line(s) the comment is anchored to.

### Challenge: mapping findings to diff positions
GitHub review comments require a `position` (line within the diff) or `line` (absolute
file line, with `side: RIGHT` for the new version). The `line` + `side: RIGHT` approach
is simpler and works as long as the file is in the diff.

### Implementation in `integrations/github-action.yml`

Replace the existing PR comment step with two steps:

**Step A — generate JSON findings**
```yaml
- name: Run tf-analyze
  id: scan
  run: |
    python3 scripts/detect.py \
      --target . \
      --format json \
      --fail-on ${{ inputs.fail-on || 'HIGH' }} \
      --show-fixes \
      > tf-analyze-findings.json || true
    echo "exit_code=$?" >> $GITHUB_OUTPUT
```

**Step B — post review comments**
```yaml
- name: Post PR suggestion comments
  if: github.event_name == 'pull_request'
  uses: actions/github-script@v7
  with:
    script: |
      const fs = require('fs');
      const findings = JSON.parse(fs.readFileSync('tf-analyze-findings.json', 'utf8'));
      const { findings: items } = findings;

      // Group by file; only comment on files changed in this PR
      const changedFiles = await github.rest.pulls.listFiles({
        owner: context.repo.owner, repo: context.repo.repo,
        pull_number: context.payload.pull_request.number,
      });
      const changedPaths = new Set(changedFiles.data.map(f => f.filename));

      // Deduplicate: one comment per (file, line) — use the highest-urgency finding
      const byLocation = new Map();
      for (const f of items) {
        if (!f.fix_hcl) continue;
        const key = `${f.file}:${f.line}`;
        const existing = byLocation.get(key);
        if (!existing || urgencyRank(f.urgency) > urgencyRank(existing.urgency)) {
          byLocation.set(key, f);
        }
      }

      function urgencyRank(u) {
        return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 }[u] ?? 0;
      }

      const URGENCY_EMOJI = { CRITICAL: '🚨', HIGH: '⚠️', MEDIUM: '💡', LOW: 'ℹ️' };

      for (const [, finding] of byLocation) {
        if (!changedPaths.has(finding.file)) continue;
        const emoji = URGENCY_EMOJI[finding.urgency] ?? '•';
        const body = [
          `${emoji} **[${finding.id}](https://github.com/${context.repo.owner}/${context.repo.repo}/blob/main/catalog/${finding.id}.yaml)** — ${finding.title}`,
          '',
          `> Urgency: \`${finding.urgency}\` · Disruption: \`${finding.fix_disruption ?? 'none'}\``,
          '',
          '```suggestion',
          finding.fix_hcl.trimEnd(),
          '```',
        ].join('\n');

        try {
          await github.rest.pulls.createReviewComment({
            owner: context.repo.owner, repo: context.repo.repo,
            pull_number: context.payload.pull_request.number,
            body,
            path: finding.file,
            line: finding.line,
            side: 'RIGHT',
          });
        } catch (e) {
          // Line not in diff (e.g. unchanged file) — fall back to issue comment
          core.warning(`Could not post suggestion for ${finding.id} at ${finding.file}:${finding.line}: ${e.message}`);
        }
      }

      // Summary comment (always posted, replaces prior)
      const critical = items.filter(f => f.urgency === 'CRITICAL').length;
      const high = items.filter(f => f.urgency === 'HIGH').length;
      const summaryBody = items.length === 0
        ? '✅ **tf-analyze**: no findings above threshold'
        : `## tf-analyze findings\n\n| Urgency | Count |\n|---------|-------|\n` +
          `| 🚨 CRITICAL | ${critical} |\n| ⚠️ HIGH | ${high} |\n\n` +
          `${items.filter(f => f.fix_hcl).length} finding(s) have inline suggestion fixes above.`;

      // Upsert summary comment
      const comments = await github.rest.issues.listComments({
        owner: context.repo.owner, repo: context.repo.repo,
        issue_number: context.payload.pull_request.number,
      });
      const prior = comments.data.find(c => c.body.startsWith('## tf-analyze findings') || c.body.startsWith('✅ **tf-analyze**'));
      if (prior) {
        await github.rest.issues.updateComment({
          owner: context.repo.owner, repo: context.repo.repo,
          comment_id: prior.id, body: summaryBody,
        });
      } else {
        await github.rest.issues.createComment({
          owner: context.repo.owner, repo: context.repo.repo,
          issue_number: context.payload.pull_request.number, body: summaryBody,
        });
      }
```

### New `inputs:` block to add at top of `github-action.yml`

```yaml
inputs:
  fail-on:
    description: 'Minimum urgency level to fail CI (CRITICAL, HIGH, MEDIUM, LOW)'
    default: 'HIGH'
  section:
    description: 'Restrict findings to a catalogue section (security, robustness, ops, …). Empty = all.'
    default: ''
  post-pr-comment:
    description: 'Post PR suggestion comments on pull_request events'
    default: 'true'
```

### Acceptance criteria
- [ ] PR on a branch containing `aws_ebs_volume` without `encrypted = true` receives an inline review comment on the correct line with a suggestion block containing `encrypted = true`
- [ ] Clicking "Apply suggestion" on GitHub commits the fix
- [ ] Findings for files not changed in the PR do not generate review comments (fall back to summary)
- [ ] Summary comment is upserted (not duplicated) across re-runs
- [ ] `inputs.fail-on: CRITICAL` causes the job to pass on HIGH findings

---

## §4 False-Positive (Clean) Fixtures

### Why fourth
Clean fixtures are the trust foundation. Before promoting the tool widely, every
`fire_if_absent` and `not_regex` rule must have a proof that it does not fire on a
correct configuration. Without this, a broken `not_regex` could silently never fire —
all positive fixtures would still pass. This is the largest gap in the current test
suite.

### Rules requiring clean fixtures (26 total)

**`fire_if_absent: true` / `not_regex:` rules (8)**

| Rule | Clean fixture — what it must contain |
|------|--------------------------------------|
| `ROB-AWS-ALB-001` | `aws_lb` with `drop_invalid_header_fields = true` |
| `SEC-AWS-DOCDB-001` | `aws_docdb_cluster` with `storage_encrypted = true` |
| `SEC-AWS-KINESIS-001` | `aws_kinesis_stream` with `encryption_type = "KMS"` |
| `SEC-AWS-REDSHIFT-001` | `aws_redshift_cluster` with `encrypted = true` |
| `SEC-AWS-IAM-003` | `aws_iam_account_password_policy` with `minimum_password_length = 14` |
| `SEC-AWS-NEPTUNE-001` | `aws_neptune_cluster` with `storage_encrypted = true` |
| `SEC-AZURE-REDIS-001` | `azurerm_redis_cache` with `enable_non_ssl_port = false` and `minimum_tls_version = "TLS1_2"` |
| `STK-AWS-EKS-005` | `aws_eks_cluster` with all 5 log types in `enabled_cluster_log_types` |

**`resource_absent` rules (18)** — clean fixture must contain the *required* resource

| Rule | Clean fixture — what it must contain |
|------|--------------------------------------|
| `ROB-AWS-BACKUP-001` | `aws_backup_plan` + `aws_iam_role` |
| `ROB-AWS-SECRETSMANAGER-001` | `aws_secretsmanager_secret_rotation` |
| `SEC-AWS-ECR-002` | `aws_ecr_lifecycle_policy` |
| `SEC-AWS-GUARDDUTY-001` | `aws_guardduty_detector` + `aws_vpc` |
| `SEC-AWS-S3-LOGGING-001` | `aws_s3_bucket_logging` |
| `SEC-AWS-SECURITYHUB-001` | `aws_securityhub_account` + `aws_vpc` |
| `SEC-AWS-S3-PUBLIC-BLOCK-001` | `aws_s3_bucket_public_access_block` with all 4 flags true |
| `SEC-AWS-WAF-001` | `aws_wafv2_web_acl_association` |
| `SEC-AWS-VPC-FLOWLOGS-001` | `aws_flow_log` |
| `SEC-AZURE-LOGGING-001` | `azurerm_monitor_diagnostic_setting` |
| `SEC-AZURE-MONITOR-001` | `azurerm_monitor_activity_log_alert` |
| `SEC-AZURE-SQL-001` | `azurerm_mssql_active_directory_administrator` |
| `SEC-GCP-LOGGING-001` | `google_project_iam_audit_config` |
| `STK-AWS-EKS-004` | `aws_iam_openid_connect_provider` + `tls_certificate` data source |
| `STK-AWS-ROUTE53-001` | `aws_route53_key_signing_key` + `aws_route53_hosted_zone_dnssec` |
| `STK-AZURE-NSG-FLOWLOG-001` | `azurerm_network_watcher_flow_log` |
| `STK-AZURE-SQL-TDE-001` | `azurerm_mssql_transparent_data_encryption` with `state = "Enabled"` |
| `SEC-AWS-IAM-003` (absent variant) | `aws_iam_account_password_policy` present |

### File naming convention
```
fixtures/SEC-AWS-EBS-001_clean/main.tf     underscore-clean suffix
```

### `self_test.py` clean pass — implementation

Add after the existing positive-finding pass:

```python
def _run_clean_pass(catalog_dir: Path, fixtures_dir: Path) -> tuple[int, int]:
    """For every *_clean fixture dir, assert its corresponding rule does NOT fire."""
    passed = failed = 0
    for clean_dir in sorted(fixtures_dir.glob("*_clean")):
        rule_id = clean_dir.name.removesuffix("_clean")
        # Load only the rule being tested to keep the scan fast
        entries = load_catalog(catalog_dir)
        entries = [e for e in entries if e["id"] == rule_id]
        if not entries:
            print(f"WARN: no catalogue entry for {rule_id} (referenced by {clean_dir.name})")
            continue
        findings = detect_corpus(clean_dir, _read_all(clean_dir), entries)
        fired = [f for f in findings if f["id"] == rule_id]
        if fired:
            print(f"FAIL {clean_dir.name}: expected zero {rule_id} findings, got {len(fired)}")
            failed += 1
        else:
            print(f"PASS {clean_dir.name}: {rule_id} correctly silent")
            passed += 1
    return passed, failed
```

### Acceptance criteria
- [ ] 26 `*_clean` fixture directories exist, each with a valid `main.tf`
- [ ] `python3 scripts/self_test.py` clean pass reports 26/26
- [ ] Running `detect.py --target fixtures/<RULE-ID>_clean` with the corresponding rule produces zero findings for that rule
- [ ] Other rules may fire on clean fixtures (that's expected — they are not comprehensive configurations)
- [ ] `tests/test_clean_fixtures.py` parametrized test passes under pytest

---

## §5 pytest Migration with Parallel Execution

### Why fifth
The current `self_test.py` is a bespoke runner. pytest gives parallel execution
(4–8× speedup), standard JUnit XML for GitHub Actions test summaries, better failure
messages, and the infrastructure for all subsequent unit tests. Doing this before items
6–8 means all new tests are written in the standard framework from the start.

### New directory structure
```
pyproject.toml                          project metadata + pytest config
tests/__init__.py                       empty
tests/conftest.py                       shared fixtures, fixture-case loader
tests/test_fixtures.py                  parametrized positive-finding tests
tests/test_clean_fixtures.py            parametrized clean fixture tests
tests/test_detection_core.py            unit tests for core functions
tests/test_attack_graph.py              unit tests for build_attack_graph()
tests/test_output_formats.py            output format + exit code tests
tests/test_schema_invariants.py         catalogue YAML invariant tests
```

### `pyproject.toml`

```toml
[project]
name = "tf-analyze"
version = "0.1.0"
description = "Terraform security and stack analysis"
requires-python = ">=3.9"

[project.scripts]
tf-analyze = "scripts.detect:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --tb=short"

[tool.pytest.markers]
slow = "marks tests as slow (deselect with -m 'not slow')"
```

### `tests/conftest.py`

```python
import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
CATALOG_DIR  = Path(__file__).parent.parent / "catalog"

def _load_fixture_cases():
    """Return list of (fixture_dir, expected_rule_ids) from self_test metadata."""
    # Import the existing FIXTURE_CASES mapping from self_test.py
    # self_test.py exposes FIXTURE_CASES = {"fixture_name": ["RULE-ID", ...], ...}
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "self_test", Path(__file__).parent.parent / "scripts" / "self_test.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return [(FIXTURES_DIR / name, ids) for name, ids in mod.FIXTURE_CASES.items()]

def _load_clean_cases():
    return [d for d in sorted(FIXTURES_DIR.glob("*_clean")) if d.is_dir()]

@pytest.fixture(scope="session")
def catalog_entries():
    from detect import load_catalog
    return load_catalog(CATALOG_DIR)

FIXTURE_CASES = _load_fixture_cases()
CLEAN_CASES = _load_clean_cases()
```

### `tests/test_fixtures.py`

```python
import pytest
from pathlib import Path
from conftest import FIXTURE_CASES, CATALOG_DIR
from detect import load_catalog, detect_corpus

@pytest.mark.parametrize("fixture_dir,expected_ids", FIXTURE_CASES,
                         ids=[d.name for d, _ in FIXTURE_CASES])
def test_fixture_fires_expected_rules(fixture_dir, expected_ids, tmp_path):
    entries = load_catalog(CATALOG_DIR)
    all_files = {p: p.read_text() for p in fixture_dir.rglob("*.tf")}
    findings = detect_corpus(fixture_dir, all_files, entries)
    fired = {f["id"] for f in findings}
    for eid in expected_ids:
        assert eid in fired, f"{fixture_dir.name}: expected {eid} to fire, got {sorted(fired)}"
```

### `tests/test_detection_core.py` — full test list

```python
# block_arg_value() — 10 tests
def test_bav_simple_string():
    assert block_arg_value('  name = "my-bucket"', "name") == "my-bucket"

def test_bav_bool_false():
    assert block_arg_value("  encrypted = false", "encrypted") == "false"

def test_bav_bool_true():
    assert block_arg_value("  enabled = true", "enabled") == "true"

def test_bav_absent_returns_none():
    assert block_arg_value('  name = "x"', "encrypted") is None

def test_bav_nested_block_returns_body():
    body = "  settings {\n    tier = \"basic\"\n  }"
    result = block_arg_value(body, "settings")
    assert "tier" in result

def test_bav_heredoc_returns_none():
    # Heredocs are not parsed by the regex path
    assert block_arg_value('  policy = <<-EOF\n  {}\n  EOF', "policy") is None

def test_bav_list_value():
    val = block_arg_value('  types = ["api", "audit"]', "types")
    assert val is not None and "audit" in val

def test_bav_var_reference_returned_raw():
    assert block_arg_value("  encrypted = var.encrypt", "encrypted") == "var.encrypt"

def test_bav_ternary_returned_raw():
    assert block_arg_value("  size = var.large ? 100 : 20", "size") == "var.large ? 100 : 20"

def test_bav_multiline_list():
    body = '  tags = {\n    Env = "prod"\n  }'
    assert block_arg_value(body, "tags") is not None

# _resolve_var_ref() — 5 tests
def test_rvr_known_default():
    assert _resolve_var_ref("var.encrypt", {"encrypt": "true"}) == "true"

def test_rvr_unknown_var_returns_original():
    assert _resolve_var_ref("var.unknown", {"encrypt": "true"}) == "var.unknown"

def test_rvr_non_var_passthrough():
    assert _resolve_var_ref("false", {}) == "false"

def test_rvr_local_passthrough():
    # local.X is not yet resolved — returned as-is until §6
    assert _resolve_var_ref("local.settings", {}) == "local.settings"

def test_rvr_empty_defaults():
    assert _resolve_var_ref("var.x", {}) == "var.x"

# _extract_var_defaults_by_dir() — 3 tests
def test_evd_extracts_default(tmp_path):
    (tmp_path / "variables.tf").write_text(
        'variable "encrypt" {\n  type = bool\n  default = true\n}\n'
    )
    result = _extract_var_defaults_by_dir({str(tmp_path / "variables.tf"): (tmp_path / "variables.tf").read_text()})
    assert result.get(str(tmp_path), {}).get("encrypt") == "true"

def test_evd_no_default_absent(tmp_path):
    (tmp_path / "variables.tf").write_text('variable "x" { type = string }\n')
    result = _extract_var_defaults_by_dir({str(tmp_path / "variables.tf"): (tmp_path / "variables.tf").read_text()})
    assert "x" not in result.get(str(tmp_path), {})

def test_evd_string_default_unquoted(tmp_path):
    (tmp_path / "v.tf").write_text('variable "env" { default = "prod" }\n')
    result = _extract_var_defaults_by_dir({str(tmp_path / "v.tf"): (tmp_path / "v.tf").read_text()})
    assert result.get(str(tmp_path), {}).get("env") == "prod"

# inline ignore suppression — 2 tests
def test_inline_ignore_suppresses_finding(tmp_path):
    tf = 'resource "aws_ebs_volume" "x" {\n  # tf-analyze:ignore SEC-AWS-EBS-001\n  size = 20\n}\n'
    (tmp_path / "main.tf").write_text(tf)
    entries = [e for e in load_catalog(CATALOG_DIR) if e["id"] == "SEC-AWS-EBS-001"]
    findings = detect_corpus(tmp_path, {str(tmp_path / "main.tf"): tf}, entries)
    assert not any(f["id"] == "SEC-AWS-EBS-001" for f in findings)

def test_inline_ignore_does_not_suppress_other_rules(tmp_path):
    tf = 'resource "aws_ebs_volume" "x" {\n  # tf-analyze:ignore SEC-AWS-EBS-001\n  size = 20\n}\n'
    (tmp_path / "main.tf").write_text(tf)
    entries = load_catalog(CATALOG_DIR)
    findings = detect_corpus(tmp_path, {str(tmp_path / "main.tf"): tf}, entries)
    # Other rules may still fire — just not SEC-AWS-EBS-001
    assert not any(f["id"] == "SEC-AWS-EBS-001" for f in findings)
```

### `tests/test_attack_graph.py`

```python
INTERNET_FIXTURE = """
resource "aws_instance" "web" {
  ami = "ami-123"
  associate_public_ip_address = true
}
resource "aws_s3_bucket" "data" {
  bucket = "data"
}
resource "aws_iam_role_policy_attachment" "attach" {
  role       = "web-role"
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}
"""

def test_internet_reachable_node_identified():
    resource_index = _parse_resource_index(INTERNET_FIXTURE)
    graph = build_attack_graph(resource_index, [])
    internet_nodes = [n for n in graph["nodes"] if n.get("internet_reachable")]
    assert any(n["id"] == "aws_instance.web" for n in internet_nodes)

def test_crown_jewel_s3_identified():
    resource_index = _parse_resource_index(INTERNET_FIXTURE)
    graph = build_attack_graph(resource_index, [])
    assert any(n.get("crown_jewel") for n in graph["nodes"]
               if n["id"] == "aws_s3_bucket.data")

def test_isolated_resource_has_no_path_to_crown_jewel():
    fixture = 'resource "aws_sqs_queue" "isolated" { name = "q" }\n'
    resource_index = _parse_resource_index(fixture)
    graph = build_attack_graph(resource_index, [])
    paths = graph.get("critical_paths", [])
    assert len(paths) == 0
```

### CI update (`.github/workflows/ci.yml`)

Replace:
```yaml
- run: python3 scripts/self_test.py
```
With:
```yaml
- run: pip install pytest pytest-xdist
- run: pytest -n auto --tb=short -q --junitxml=test-results.xml
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: test-results
    path: test-results.xml
```

### `scripts/self_test.py` backwards-compat shim

```python
#!/usr/bin/env python3
"""Backwards-compatible shim: delegates to pytest."""
import subprocess, sys
result = subprocess.run(["pytest", "--tb=short", "-q", *sys.argv[1:]])
sys.exit(result.returncode)
```

### Acceptance criteria
- [ ] `pytest -n auto` runs all 192+ tests in parallel; all pass in < 10s on a 4-core machine
- [ ] `pytest tests/test_detection_core.py` passes all 20 unit tests
- [ ] `pytest tests/test_attack_graph.py` passes all graph tests
- [ ] `pytest --junitxml=test-results.xml` produces valid XML consumed by GitHub Actions test summary
- [ ] `python3 scripts/self_test.py` still works (exit 0 on clean)
- [ ] CI shows per-test results in the Actions "Tests" tab

---

## §6 Custom Rules Support

### Why sixth
Community contribution is the primary growth multiplier after viral discovery. Any team
that can encode their own standards (naming conventions, required tags, org-specific
deprecations) without forking will do so — and then share their rules.

### `.tf-analyze.yaml` schema

```yaml
# Project-level tf-analyze configuration.
# Place at the root of the Terraform repository being scanned.

# Directory containing additional catalogue YAML files.
# IDs must use the CUSTOM-* prefix (e.g. CUSTOM-TAGS-001).
rules_dir: .tf-analyze-rules/

# Rule IDs to suppress project-wide (equivalent to putting
# # tf-analyze:ignore <ID> on every resource in the repo).
ignore_rules:
  - STYLE-DESC-001

# Override thresholds used by parameterised rules.
thresholds:
  password_min_length: 14      # default: 14
  backup_retention_days: 7     # default: 7
  log_retention_days: 90       # default: 90
```

### `detect.py` changes

**New function: `_load_project_config(target: Path) -> dict`** (~30 lines)
```python
def _load_project_config(target: Path) -> dict:
    config_path = target / ".tf-analyze.yaml"
    if not config_path.exists():
        return {}
    try:
        data = load_yaml(config_path.read_text()) or {}
    except Exception as e:
        print(f"WARNING: cannot parse .tf-analyze.yaml: {e}", file=sys.stderr)
        return {}
    return data
```

**Updated `load_catalog()` signature:**
```python
def load_catalog(
    catalog_dir: Path,
    include_stubs: bool = False,
    strict: bool = False,
    extra_rules_dir: Path | None = None,      # NEW
) -> list[dict]:
```

Inside `load_catalog()`, after loading built-in entries, append:
```python
if extra_rules_dir and extra_rules_dir.is_dir():
    for yml in sorted(extra_rules_dir.glob("*.yaml")):
        # same load + validate loop
        # enforce CUSTOM-* prefix
        eid = data.get("id", "")
        if not eid.startswith("CUSTOM-"):
            print(f"WARNING: custom rule {yml.name} id must start with CUSTOM-; skipping", file=sys.stderr)
            continue
        entries.append(data)
```

**New CLI flag:**
```python
ap.add_argument("--config", default=None, metavar="PATH",
    help="Path to .tf-analyze.yaml project config (default: auto-discover in target dir)")
```

**New meta-command:**
```python
ap.add_argument("--init", action="store_true",
    help="Scaffold .tf-analyze.yaml and .tf-analyze-rules/CUSTOM-EXAMPLE-001.yaml in the target directory")
```

**Apply project-level ignores in `detect_corpus()`:**
```python
project_ignores = set(project_config.get("ignore_rules", []))
findings = [f for f in findings if f["id"] not in project_ignores]
```

**Pass flow in `main()`:**
```python
target = Path(args.targets[0])
project_config = _load_project_config(target) if not args.config \
    else _load_project_config(Path(args.config).parent)
extra_rules_dir = Path(project_config.get("rules_dir", "")) \
    if project_config.get("rules_dir") else None
entries = load_catalog(catalog_dir, extra_rules_dir=extra_rules_dir)
```

### `--init` scaffolded files

**`.tf-analyze.yaml`:**
```yaml
# tf-analyze project configuration
# rules_dir: .tf-analyze-rules/
# ignore_rules: []
# thresholds:
#   password_min_length: 14
```

**`.tf-analyze-rules/CUSTOM-EXAMPLE-001.yaml`:**
```yaml
id: CUSTOM-EXAMPLE-001
title: "Example: resource missing required Owner tag"
section: ops
default_urgency: MEDIUM
blast_radius: single-resource
status: active
patterns:
  - kind: resource_missing_arg
    resource: aws_instance
    arg: tags.Owner
    description: EC2 instance missing Owner tag required by org policy
recommendation: |
  Add an Owner tag identifying the team responsible for this resource.
      resource "aws_instance" "app" {
        tags = { Owner = "platform-team" }
      }
verification: |
  `aws ec2 describe-instances --query 'Reservations[*].Instances[*].Tags'`
  must include Owner for all instances.
fix_hcl: |
  resource "aws_instance" "app" {
    tags = {
      Owner       = "platform-team"
      Environment = var.environment
    }
  }
fix_disruption: none
fixtures: []
```

### `tests/test_custom_rules.py`

```python
def test_custom_rule_fires(tmp_path):
    # Write a minimal custom catalogue entry
    rules_dir = tmp_path / ".tf-analyze-rules"
    rules_dir.mkdir()
    (rules_dir / "CUSTOM-TEST-001.yaml").write_text("""
id: CUSTOM-TEST-001
title: "Test rule"
section: ops
default_urgency: LOW
blast_radius: single-resource
status: active
patterns:
  - kind: resource_arg
    resource: aws_instance
    arg: instance_type
    regex: "^t2\\."
    description: t2 instances are legacy
recommendation: Upgrade to t3
verification: Check instance type
fix_hcl: |
  resource "aws_instance" "x" { instance_type = "t3.micro" }
fix_disruption: forces_replacement
fixtures: []
""")
    (tmp_path / "main.tf").write_text(
        'resource "aws_instance" "x" { instance_type = "t2.micro" }\n'
    )
    config = {"rules_dir": str(rules_dir)}
    entries = load_catalog(CATALOG_DIR, extra_rules_dir=rules_dir)
    findings = detect_corpus(tmp_path, {str(tmp_path / "main.tf"): (tmp_path / "main.tf").read_text()}, entries)
    assert any(f["id"] == "CUSTOM-TEST-001" for f in findings)

def test_ignore_rules_suppresses_builtin(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "x" { bucket = "test" }\n'
    )
    # STYLE-DESC-001 would normally fire (missing variable/output descriptions on parent)
    # Apply ignore via project config
    entries = load_catalog(CATALOG_DIR)
    all_files = {str(tmp_path / "main.tf"): (tmp_path / "main.tf").read_text()}
    all_findings = detect_corpus(tmp_path, all_files, entries)
    filtered = [f for f in all_findings if f["id"] != "STYLE-DESC-001"]
    assert not any(f["id"] == "STYLE-DESC-001" for f in filtered)

def test_custom_id_must_have_custom_prefix(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "BAD-001.yaml").write_text("id: BAD-001\ntitle: x\nsection: ops\n"
        "default_urgency: LOW\nblast_radius: module\nstatus: active\n"
        "patterns: []\nrecommendation: x\nverification: x\nfixtures: []\n")
    import io, sys
    stderr = io.StringIO()
    sys.stderr = stderr
    load_catalog(CATALOG_DIR, extra_rules_dir=rules_dir)
    sys.stderr = sys.__stderr__
    assert "CUSTOM-" in stderr.getvalue()
```

### Acceptance criteria
- [ ] `detect.py --init` in an empty directory creates `.tf-analyze.yaml` and `.tf-analyze-rules/CUSTOM-EXAMPLE-001.yaml`
- [ ] A `CUSTOM-TAGS-001` rule in `.tf-analyze-rules/` fires on a matching resource
- [ ] A rule whose id doesn't start with `CUSTOM-` is rejected with a clear warning
- [ ] `ignore_rules: [STYLE-DESC-001]` in `.tf-analyze.yaml` suppresses `STYLE-DESC-001` findings
- [ ] `tests/test_custom_rules.py` passes all 3 tests
- [ ] `detect.py --list-rules` shows `CUSTOM-*` entries after built-in rules

---

## §7 LSP Server Mode (`--lsp`)

### Why seventh
The VS Code extension currently spawns `detect.py` on every save — cold-start overhead
of ~0.3s. An LSP server stays resident, caches the catalogue in memory, and serves
diagnostics in ~50ms. Beyond VS Code, any LSP-capable editor (Neovim, Emacs,
JetBrains, Zed) gets the same integration for free.

### Protocol surface (minimal viable LSP)

Only 7 methods needed for full diagnostic + quick-fix support:

| Method | Direction | Action |
|--------|-----------|--------|
| `initialize` | client→server | Return capabilities |
| `initialized` | client→server | No-op |
| `textDocument/didOpen` | client→server | Scan URI, publish diagnostics |
| `textDocument/didSave` | client→server | Re-scan URI, publish diagnostics |
| `textDocument/didClose` | client→server | Clear diagnostics for URI |
| `textDocument/codeAction` | client→server | Return WorkspaceEdit quick-fixes |
| `shutdown` + `exit` | client→server | Graceful stop |

### Implementation in `detect.py` — `_run_lsp_server()`

```python
def _run_lsp_server(catalog_dir: Path, project_config: dict) -> None:
    """JSON-RPC 2.0 LSP server on stdin/stdout."""
    import asyncio, json, struct

    entries = load_catalog(catalog_dir)
    # Cache: uri → list[dict finding]
    _diagnostics: dict[str, list] = {}

    def _uri_to_path(uri: str) -> Path:
        return Path(uri.removeprefix("file://"))

    def _scan_uri(uri: str) -> list[dict]:
        path = _uri_to_path(uri)
        if not path.exists() or not path.suffix == ".tf":
            return []
        text = path.read_text()
        target = path.parent
        all_files = {str(p): p.read_text()
                     for p in target.glob("*.tf") if p.exists()}
        var_defaults = _extract_var_defaults_by_dir(all_files)
        return detect_in_file(path, text, entries, var_defaults.get(str(target), {}))

    def _findings_to_diagnostics(findings: list[dict]) -> list[dict]:
        sev_map = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        diags = []
        for f in findings:
            line = max(0, f["line"] - 1)
            diags.append({
                "range": {"start": {"line": line, "character": 0},
                           "end":   {"line": line, "character": 9999}},
                "severity": sev_map.get(f.get("urgency", "LOW"), 3),
                "code": f["id"],
                "source": "tf-analyze",
                "message": f"{f['id']}: {f.get('title', '')}",
            })
        return diags

    def _read_message() -> dict | None:
        header = b""
        while not header.endswith(b"\r\n\r\n"):
            ch = sys.stdin.buffer.read(1)
            if not ch:
                return None
            header += ch
        length = int(re.search(rb"Content-Length: (\d+)", header).group(1))
        body = sys.stdin.buffer.read(length)
        return json.loads(body)

    def _send(obj: dict) -> None:
        body = json.dumps(obj).encode()
        sys.stdout.buffer.write(
            f"Content-Length: {len(body)}\r\n\r\n".encode() + body
        )
        sys.stdout.buffer.flush()

    def _notify(method: str, params: dict) -> None:
        _send({"jsonrpc": "2.0", "method": method, "params": params})

    _initialized = False
    while True:
        msg = _read_message()
        if msg is None:
            break
        method = msg.get("method", "")
        mid = msg.get("id")

        if method == "initialize":
            _send({
                "jsonrpc": "2.0", "id": mid,
                "result": {
                    "capabilities": {
                        "textDocumentSync": {"openClose": True, "save": True},
                        "codeActionProvider": True,
                    },
                    "serverInfo": {"name": "tf-analyze", "version": "0.1.0"},
                }
            })

        elif method == "initialized":
            _initialized = True

        elif method in ("textDocument/didOpen", "textDocument/didSave"):
            uri = msg["params"]["textDocument"]["uri"]
            findings = _scan_uri(uri)
            _diagnostics[uri] = findings
            # Enrich findings with urgency from catalogue
            id_map = {e["id"]: e for e in entries}
            for f in findings:
                f.setdefault("urgency", id_map.get(f["id"], {}).get("default_urgency", "LOW"))
            _notify("textDocument/publishDiagnostics", {
                "uri": uri,
                "diagnostics": _findings_to_diagnostics(findings),
            })

        elif method == "textDocument/didClose":
            uri = msg["params"]["textDocument"]["uri"]
            _diagnostics.pop(uri, None)
            _notify("textDocument/publishDiagnostics", {"uri": uri, "diagnostics": []})

        elif method == "textDocument/codeAction":
            uri = msg["params"]["textDocument"]["uri"]
            req_range = msg["params"]["range"]
            req_line = req_range["start"]["line"] + 1  # convert to 1-based
            findings = _diagnostics.get(uri, [])
            id_map = {e["id"]: e for e in entries}
            actions = []
            for f in findings:
                if abs(f["line"] - req_line) > 2:
                    continue
                entry = id_map.get(f["id"], {})
                fix_hcl = entry.get("fix_hcl")
                if not fix_hcl:
                    continue
                actions.append({
                    "title": f"tf-analyze fix: {f['id']}",
                    "kind": "quickfix",
                    "edit": {
                        "changes": {
                            uri: [{
                                "range": {
                                    "start": {"line": f["line"] - 1, "character": 0},
                                    "end":   {"line": f["line"] - 1, "character": 0},
                                },
                                "newText": f"\n# tf-analyze fix for {f['id']}:\n{fix_hcl}\n",
                            }]
                        }
                    }
                })
            _send({"jsonrpc": "2.0", "id": mid, "result": actions})

        elif method == "shutdown":
            _send({"jsonrpc": "2.0", "id": mid, "result": None})

        elif method == "exit":
            sys.exit(0)

        elif mid is not None:
            _send({"jsonrpc": "2.0", "id": mid,
                   "error": {"code": -32601, "message": f"Method not found: {method}"}})
```

Add to `main()` after argparse:
```python
if args.lsp:
    _run_lsp_server(catalog_dir, project_config)
    return
```

### `docs/lsp.md` — Neovim config

```lua
-- ~/.config/nvim/lua/plugins/tf-analyze.lua
require("lspconfig.configs").tf_analyze = {
  default_config = {
    cmd = { "python3", "/path/to/tf-analyze/scripts/detect.py", "--lsp" },
    filetypes = { "terraform" },
    root_dir = require("lspconfig.util").root_pattern(".terraform", ".git"),
    settings = {},
  },
}
require("lspconfig").tf_analyze.setup({})
```

### Acceptance criteria
- [ ] `echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}' | python3 scripts/detect.py --lsp` returns a valid `initialize` response within 2s
- [ ] Opening a `.tf` file in Neovim with the above config shows squiggles within 1s of save
- [ ] `codeAction` returns `WorkspaceEdit` for a finding with `fix_hcl`
- [ ] Server stays resident across 50 sequential `didSave` events without memory growth > 50MB
- [ ] `shutdown` + `exit` sequence terminates cleanly (exit code 0)

---

## §8 Interactive Web Demo

### Why eighth
The demo is the top-of-funnel "try before you buy" experience. Blog posts, tweets, and
conference demos all want a live URL. Zero install, no account, results in 10 seconds.
The attack graph SVG is visually unique and will be shared.

### Architecture

```
demo/
  app.py              FastAPI backend
  index.html          single-page frontend (no build step)
  requirements.txt    fastapi uvicorn python-multipart
  Dockerfile
  fly.toml
```

### `demo/app.py`

```python
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import subprocess, tempfile, shutil, re, json, time
from pathlib import Path
from collections import defaultdict

app = FastAPI()
DETECT = Path(__file__).parent.parent / "scripts" / "detect.py"
CATALOG = Path(__file__).parent.parent / "catalog"

# Simple in-memory rate limiter: 10 req/min per IP
_rate: dict[str, list[float]] = defaultdict(list)

def _rate_check(ip: str) -> bool:
    now = time.time()
    _rate[ip] = [t for t in _rate[ip] if now - t < 60]
    if len(_rate[ip]) >= 10:
        return False
    _rate[ip].append(now)
    return True

class ScanHcl(BaseModel):
    hcl: str

class ScanRepo(BaseModel):
    repo: str  # https://github.com/owner/repo

@app.post("/scan/hcl")
async def scan_hcl(body: ScanHcl, request: Request):
    if not _rate_check(request.client.host):
        raise HTTPException(429, "Rate limit exceeded")
    if len(body.hcl) > 50_000:
        raise HTTPException(400, "HCL too large (max 50KB)")
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "main.tf").write_text(body.hcl)
        return _run_scan(d)

@app.post("/scan/repo")
async def scan_repo(body: ScanRepo, request: Request):
    if not _rate_check(request.client.host):
        raise HTTPException(429, "Rate limit exceeded")
    url = body.repo.strip()
    if not re.match(r"https://(github|gitlab)\.com/[\w.-]+/[\w.-]+$", url):
        raise HTTPException(400, "Only github.com and gitlab.com repos are supported")
    with tempfile.TemporaryDirectory() as d:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", url, d],
            capture_output=True, timeout=30,
        )
        if result.returncode != 0:
            raise HTTPException(400, "Could not clone repository")
        return _run_scan(d)

def _run_scan(target_dir: str) -> dict:
    result = subprocess.run(
        ["python3", str(DETECT),
         "--target", target_dir,
         "--catalog", str(CATALOG),
         "--format", "json",
         "--attack-graph"],
        capture_output=True, text=True, timeout=30,
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise HTTPException(500, "Scanner returned invalid JSON")
    return data

@app.get("/", response_class=HTMLResponse)
async def index():
    return (Path(__file__).parent / "index.html").read_text()
```

### `demo/index.html` — structure

The page has three columns:
1. **Left** — HCL editor (CodeMirror 6 with HCL syntax) + repo URL input + "Scan" button
2. **Centre** — Findings table: columns `Urgency | ID | Title | File:Line | Fix?`; sortable; clicking a row expands `fix_hcl` below it
3. **Right** — d3.js attack graph SVG; nodes coloured by type; pan+zoom; click to inspect

JavaScript flow:
```javascript
async function scan() {
  const hcl = editor.state.doc.toString();
  const resp = await fetch('/scan/hcl', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ hcl }),
  });
  const data = await resp.json();
  renderFindings(data.findings);
  renderGraph(data.attack_graph);
}
```

The attack graph uses the same d3.js force layout as the VS Code webview (shared
`media/attack-graph.js` — symlinked or copied into `demo/static/`).

### `demo/Dockerfile`

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
COPY ../scripts/detect.py ./scripts/
COPY ../catalog/ ./catalog/
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
```

### `demo/fly.toml`

```toml
app = "tf-analyze-demo"
primary_region = "iad"

[build]
  dockerfile = "Dockerfile"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 0   # scale to zero when idle

[resources]
  memory = "512mb"
  cpus = 1
```

Deploy with `fly deploy` from the `demo/` directory. Cold start < 3s.

### Acceptance criteria
- [ ] `uvicorn demo.app:app --reload` starts without errors
- [ ] `POST /scan/hcl` with a minimal `aws_ebs_volume` returns findings JSON including `SEC-AWS-EBS-001`
- [ ] `POST /scan/hcl` with fully-correct HCL returns `{"findings": [], "attack_graph": {"nodes": [], "edges": []}}`
- [ ] `POST /scan/repo` with a known-bad public repo returns findings
- [ ] Rate limiting: 11th request in < 60s returns HTTP 429
- [ ] Malformed repo URL returns HTTP 400 (not 500)
- [ ] Attack graph SVG renders in browser; nodes are draggable
- [ ] `fly deploy` from `demo/` succeeds; app accessible at `https://tf-analyze-demo.fly.dev`
- [ ] "Try the demo" link is in `README.md`

---

## Dependency graph

```
#4 Clean fixtures ─────┐
#5 pytest migration ───┼──► All future tests written in pytest + CI fixed
#6 Custom rules ───────┘
       │
       ▼
#7 LSP server ─────────────► Every editor gets diagnostics
#1 VS Code extension ──────► Attack graph webview needs §1 compiled first
       │
       ▼
#2 Docker image ───────────► §8 web demo uses detect.py from same image layer
       │
       ▼
#3 PR suggestion blocks ───► Depends on Action already running (pre-existing)
#8 Web demo ───────────────► Uses detect.py + d3.js from §1's attack graph work
```

Items #4 and #5 can run in parallel.
Items #1, #2, #3 are independent and can run in parallel once #4/#5 are done.
Item #6 is a detect.py change; do before #7 (LSP picks up custom rules automatically).
Item #8 reuses the d3.js graph code from #1 — do after #1.

---

## Verification: done when all 8 items pass

```bash
# §1
code --install-extension hashicorp.tf-analyze   # Marketplace install works
# §2
docker run --rm ghcr.io/chrisadkin8/tf-analyze --list-rules | grep "SEC-AWS"
# §3  open a PR with an unencrypted EBS volume; confirm suggestion block appears
# §4
pytest tests/test_clean_fixtures.py -v          # 26 clean fixtures pass
# §5
pytest -n auto --tb=short -q                    # all tests pass in parallel
# §6
echo "ignore_rules: [STYLE-DESC-001]" > /tmp/test/.tf-analyze.yaml
python3 scripts/detect.py --target /tmp/test --config /tmp/test/.tf-analyze.yaml
# §7
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}' \
  | python3 scripts/detect.py --lsp | python3 -m json.tool
# §8
curl -s -X POST https://tf-analyze-demo.fly.dev/scan/hcl \
  -H 'Content-Type: application/json' \
  -d '{"hcl":"resource \"aws_ebs_volume\" \"x\" { size = 20 }"}' \
  | python3 -m json.tool | grep SEC-AWS-EBS-001
```
