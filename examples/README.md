# `examples/`

Three corpora that serve as both engine smoke tests and end-to-end demos for the surfaces that do graph reasoning across multiple resources.

| Directory | Purpose | What it exercises |
|---|---|---|
| [`terragoat/`](./terragoat/) | Comprehensive vulnerability corpus | OWASP-Top-10-organised; 30 files; multi-cloud (AWS / GCP / Azure). Engine smoke test (gated on **274** findings) and the broadest demo for first-time users. |
| [`module-reuse-demo/`](./module-reuse-demo/) | Module Reuse Advisor showcase | 5 dirs hand-rolled across 3 clouds + 2 negative cases. Exercises the [`📦 Module Reuse`](../docs/vscode-extension.md) panel end-to-end with all three confidence-badge tiers visible. |
| [`attack-graph-demo/`](./attack-graph-demo/) | Attack Graph showcase | Multi-tier AWS app: ALB → EC2 → IAM → S3 / Secrets / RDS. 19 nodes, 13 edges, 6 internet-reachable, 3 crown jewels. Exercises the [`🛤 Attack Graph`](../docs/vscode-extension.md) panel and the d3 demo. |

## Choosing one

- **First time using the tool?** Open `terragoat/`. Broadest coverage; reports look most like a real production audit.
- **Pitching the Module Reuse Advisor?** Open `module-reuse-demo/`. The panel renders three rule-grouped sections with five rows; the high/medium/low confidence badges make for a clean screenshot.
- **Pitching the Attack Graph?** Open `attack-graph-demo/`. The d3 view shows the canonical `INTERNET → public-EC2 → IAM-role → crown-jewels` reachability chain that's the engine's most differentiated capability vs. `tfsec` / `checkov`.

## Running any of them

```sh
# Engine smoke test (text output)
python3 scripts/detect.py --target examples/<demo-name>

# Attack graph (only meaningful for terragoat + attack-graph-demo)
python3 scripts/detect.py --target examples/<demo-name> --attack-graph --format html > /tmp/report.html

# JSON output (consumed by the VS Code extension panels)
python3 scripts/detect.py --target examples/<demo-name> --format json --show-info
```

The VS Code extension auto-discovers any directory you open as a workspace; nothing demo-specific is required to wire them up.

## Drift-gates

Each demo's expected output (finding count, attack-graph shape) is locked in `tests/test_examples_demos.py`. A catalogue change that shifts those numbers fails the local pytest run; updating the demo's README is the corrective action. This mirrors the count-stability approach `terragoat/` already uses — keeps user-visible documentation in sync with what the engine actually produces.
