# `terraform-provider-tfanalyze`

A Terraform provider that wraps the [`tf-analyze`](https://github.com/ChrisAdkin8/tf-analyze)
engine. The headline use case: gate `terraform apply` on a clean static
scan **without external CI infrastructure** by running the engine at
plan time and using the score / grade / counts in `precondition`
blocks.

## Status

**v1 — data source only.** The `tfanalyze_scan` data source runs the
engine and exposes `score`, `grade`, per-tier finding counts, and the
full JSON report. Resource shapes (`tfanalyze_gate`,
`tfanalyze_apply_fixes`) are on the roadmap but not in v1.

## Quickstart

```hcl
terraform {
  required_providers {
    tfanalyze = {
      source = "ChrisAdkin8/tfanalyze"
    }
  }
}

provider "tfanalyze" {
  # Defaults: $TFA_DETECT_PY → ~/.tf-analyze/scripts/detect.py
}

data "tfanalyze_scan" "this" {
  target       = path.module
  attack_graph = true
}

resource "null_resource" "gate" {
  lifecycle {
    precondition {
      condition     = data.tfanalyze_scan.this.high_count == 0
      error_message = "tf-analyze: HIGH findings present — fix before applying."
    }
  }
}
```

See [`examples/data-sources/tfanalyze_scan/`](./examples/data-sources/tfanalyze_scan/)
for the full worked example.

## Build from source

```sh
cd terraform-provider
go build -o terraform-provider-tfanalyze
```

To use the local build, install it under your developer override path:

```sh
mkdir -p ~/.terraform.d/plugins/registry.terraform.io/ChrisAdkin8/tfanalyze/0.1.0/$(go env GOOS)_$(go env GOARCH)
cp terraform-provider-tfanalyze ~/.terraform.d/plugins/registry.terraform.io/ChrisAdkin8/tfanalyze/0.1.0/$(go env GOOS)_$(go env GOARCH)/
```

Or use `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides {
    "ChrisAdkin8/tfanalyze" = "/path/to/terraform-provider-tfanalyze/build/dir"
  }
  direct {}
}
```

Then `terraform init` will pick up your local build instead of the registry.

## Configuration

| Provider attribute | Default | Description |
|---|---|---|
| `engine_command` | `python3` | Executable used to run the engine. |
| `script_path` | `$TFA_DETECT_PY` → `~/.tf-analyze/scripts/detect.py` | Absolute path to `detect.py`. |

| Data source attribute | Required | Description |
|---|---|---|
| `target` | yes | Workspace path (absolute or `path.module`). |
| `mode` | no | `static` (default), `diff`, `plan`, `pr-review`. |
| `show_info` | no | Include INFO-tier (Module Reuse) findings. Default `false`. |
| `attack_graph` | no | Build the attack graph and promote critical-path findings. |
| `script_path` | no | Per-data-source override of the provider-level setting. |
| `compliance_framework` | no | Render a compliance gap report against `cis` / `pci_dss` / `soc2` / `owasp_iac` / `all`. Surfaces in `compliance_report`. The `owasp_iac` choice maps the [OWASP IaC Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) static-analysable items. |

| Computed output | Type | Description |
|---|---|---|
| `score` | number | 0–100, higher better. |
| `grade` | string | `A`, `B`, `B-`, `C`, `D`, `F`. |
| `scoring_version` | number | Engine scoring version, pinned. |
| `total_findings` | number | Sum of all tier counts. |
| `critical_count` / `high_count` / `medium_count` / `low_count` / `info_count` | number | Per-tier counts. |
| `findings_json` | string | Full findings list as JSON. `jsondecode()` to inspect. |
| `json_report` | string | Full engine JSON output (summary + findings + graph). |
| `compliance_report` | string | Plain-text compliance gap report. Empty unless `compliance_framework` was set. Pasteable into `precondition.error_message` for human-readable plan failures. |

## Why a Terraform provider

The engine already ships as a CLI, a GitHub Action, a Docker image, a
pre-commit hook, an LSP server, a VS Code extension, an HCP Terraform
Run Task, an MCP server, and a badge service. Each of those is an
external surface — the user has to set up CI, install a hook, deploy a
container.

The provider closes the last gap: the engine becomes a Terraform-native
data source that lives **inside the same plan/apply cycle** that's
deploying the infrastructure. No external system to wire up; no
asynchronous report to chase down. The `terraform plan` output itself
tells you whether the workspace is ready to ship.
