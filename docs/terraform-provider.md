# Terraform provider

The `tfanalyze` Terraform provider exposes a single data source —
`tfanalyze_scan` — that runs the engine at plan time and surfaces the
score, letter grade, per-tier finding counts, and full findings JSON
to the calling configuration. Plans and applies can then be gated on a
clean scan via `precondition` blocks, **without GitHub Actions, without
external CI, without extra credentials**.

Source lives at
[`terraform-provider/`](https://github.com/ChrisAdkin8/tf-analyze/tree/main/terraform-provider)
and is structured as a standalone Go module so the engine itself stays
stdlib-Python.

## Why a provider on top of the GitHub Action

The Action runs in CI; the provider runs at `terraform plan` and
`terraform apply` time. That means a developer running `terraform
apply` from a laptop gets the same gate the CI gets, with no
out-of-band tooling. The provider also returns the full engine JSON
(`json_report`), so you can drive richer logic from the same scan —
choose a `count` based on the score, fan out a `for_each` over
critical findings, or paste the rendered compliance report into a
plan-failure message.

## Install

The provider shells out to `detect.py`; it does not bundle the engine.
Install the engine once per machine, then reference the provider in
your configuration:

```sh
git clone https://github.com/ChrisAdkin8/tf-analyze.git ~/.tf-analyze
export TFA_DETECT_PY="$HOME/.tf-analyze/scripts/detect.py"
```

Then in your Terraform configuration:

```terraform
terraform {
  required_providers {
    tfanalyze = {
      source = "ChrisAdkin8/tfanalyze"
    }
  }
}

provider "tfanalyze" {
  # Defaults: $TFA_DETECT_PY then ~/.tf-analyze/scripts/detect.py.
  # Override only when running outside the standard install layout.
  # script_path = "/path/to/detect.py"
}
```

The data source surfaces a clear diagnostic when neither
`TFA_DETECT_PY` nor `script_path` is set, so misconfiguration fails
loudly rather than silently.

## Quick start: gate `apply` on a clean scan

```terraform
data "tfanalyze_scan" "this" {
  target = path.module
}

resource "null_resource" "gate" {
  triggers = { score = data.tfanalyze_scan.this.score }

  lifecycle {
    precondition {
      condition     = data.tfanalyze_scan.this.high_count == 0 && data.tfanalyze_scan.this.critical_count == 0
      error_message = "tf-analyze: ${data.tfanalyze_scan.this.critical_count} CRITICAL · ${data.tfanalyze_scan.this.high_count} HIGH findings present."
    }
  }
}
```

`null_resource` is a load-bearing carrier for the `precondition` block —
its `triggers = { score = ... }` keeps the resource bound to the score
so a state-only change re-evaluates the gate.

## Compliance gate (Round 30 P0.1)

Set `compliance_framework` to also run a compliance gap report; the
rendered text appears in `compliance_report` and is paste-ready for
embedding in a plan-failure message.

```terraform
data "tfanalyze_scan" "owasp_iac" {
  target               = path.module
  compliance_framework = "owasp_iac"   # cis | pci_dss | soc2 | owasp_iac | all
}

resource "null_resource" "owasp_iac_gate" {
  triggers = { report = data.tfanalyze_scan.owasp_iac.compliance_report }

  lifecycle {
    precondition {
      condition     = data.tfanalyze_scan.owasp_iac.high_count == 0
      error_message = "OWASP IaC compliance gate failed.\n\n${data.tfanalyze_scan.owasp_iac.compliance_report}\n\nFix or suppress the failing controls before applying."
    }
  }
}
```

Full file at
[`examples/data-sources/tfanalyze_scan/compliance-gate.tf`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/terraform-provider/examples/data-sources/tfanalyze_scan/compliance-gate.tf).

## Schema

### Inputs

| Argument | Type | Required | Purpose |
|---|---|---|---|
| `target` | string | yes | Workspace path to scan. `path.module` is the typical value. |
| `mode` | string | no | One of `static` (default), `diff`, `plan`, `pr-review`. `fleet` and `trend` are not supported by the data source. |
| `show_info` | bool | no | Include INFO-tier findings (Module Reuse advisories, etc.). Default `false`. |
| `attack_graph` | bool | no | Build the internet → crown-jewels graph and promote critical-path findings. Default `false`. |
| `compliance_framework` | string | no | When set, populates `compliance_report` with the rendered gap report. |
| `script_path` | string | no | Per-data-source override for `detect.py`; falls back to provider-block setting. |

### Outputs

| Attribute | Type | Purpose |
|---|---|---|
| `score` | number | Workspace score, 0–100. Higher is better. |
| `grade` | string | `A`, `B`, `B-`, `C`, `D`, or `F`. |
| `scoring_version` | number | Engine scoring formula version; pinned so a downstream gate can detect a formula change. |
| `total_findings` | number | Sum of all tiers. |
| `critical_count` / `high_count` / `medium_count` / `low_count` / `info_count` | number | Per-tier finding counts. |
| `findings_json` | string | Full findings list as a JSON string. `jsondecode()` to inspect individual entries. |
| `json_report` | string | Full engine JSON (summary + findings + optional graph). |
| `compliance_report` | string | Rendered compliance gap report; empty unless `compliance_framework` is set. |

## Registry-style reference docs

Generated registry pages live under
[`terraform-provider/docs/`](https://github.com/ChrisAdkin8/tf-analyze/tree/main/terraform-provider/docs)
(`index.md` + `data-sources/scan.md`). Round 30 P0.1 populated this
directory — before then the Terraform Registry page would have rendered
with no body. Two drift-gate tests in `tests/test_terraform_provider.py`
keep the docs / examples / engine schema in sync going forward.

## Build + tests

```sh
cd terraform-provider
go build -o /tmp/terraform-provider-tfanalyze .
go test ./...
```

Cross-validation tests in `tests/test_terraform_provider.py` (11 cases)
confirm the Go module compiles, the binary boots, the example files
exist, and the registry docs are populated. Auto-skipped when `go`
isn't on PATH so CI environments without Go can still run the suite.

## Failure modes and diagnostics

The provider distinguishes three distinct failure paths so a downstream
`precondition` block (or a human reading `terraform plan` output) can
tell them apart instead of treating every empty `compliance_report` or
`findings_json` the same.

### Compliance gap report failed (R30.11)

A compliance subprocess that exits ≥ 2 (engine crash, framework typo,
catalogue load failure) raises a **hard error** via
`resp.Diagnostics.AddError`. The data source's state is not populated;
`terraform plan` halts. This was promoted from `AddWarning` in R30.11
because the prior shape silently produced
`compliance_report = ""`, and a user gating `terraform apply` on
`length(data.tfanalyze_scan.x.compliance_report) > 0` would pass the
gate even though compliance never actually ran.

### Compliance gap report cancelled (R30.12)

If the parent `terraform plan` is aborted (Ctrl-C, IDE cancellation,
CI timeout) **before** the compliance subprocess finishes, the
context-cancellation error is surfaced as a distinct diagnostic:
`"compliance gap report cancelled — the parent terraform operation
was cancelled before the compliance subprocess finished."`. This
distinguishes an aborted-but-otherwise-healthy run from a
runtime-crashed scan, and prevents an HCL `precondition` from
misreading the empty result as "compliance ran clean."

### `findings_json` serialisation failure (R30.12)

A non-serialisable field in the engine's output (defensive: the engine
emits only stdlib-JSON-compatible types today, but a future engine
field could regress) raises **`failed to serialise findings to JSON`**
as `AddError`. The prior code swallowed the marshal error via `_` and
produced an empty `findings_json` string; the new shape forces the
operator to notice the engine contract was violated. The diagnostic
includes the underlying error and a pointer to file an issue.

All three diagnostics are checked by the test suite under
`tests/test_terraform_provider.py`.
