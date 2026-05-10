---
page_title: "tfanalyze_scan Data Source - tfanalyze"
description: |-
  Run a tf-analyze scan over a Terraform workspace at plan time. Returns the engine's score / grade / counts plus the full findings JSON, suitable for `precondition` blocks that gate apply on a clean scan.
---

# tfanalyze_scan (Data Source)

Run a tf-analyze scan over a Terraform workspace at plan time. Returns the
engine's `score` (0–100), letter `grade`, per-tier finding counts, and the
full findings JSON. Use any of these in a `precondition` block — or as a
`count` expression — to gate `apply` on a clean scan without external CI
infrastructure.

When `compliance_framework` is set, the data source also runs the engine's
compliance gap report (`cis` / `pci_dss` / `soc2` / `owasp_iac` / `all`) and
exposes the rendered text in `compliance_report`. That text is paste-ready for
embedding in a `precondition.error_message` so the plan failure surfaces a
human-readable framework breakdown.

## Example Usage

### Basic — gate on critical / high findings

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

### Compliance gate — fail the plan with a framework breakdown

```terraform
data "tfanalyze_scan" "owasp_iac" {
  target               = path.module
  compliance_framework = "owasp_iac"
}

resource "null_resource" "owasp_gate" {
  triggers = { report = data.tfanalyze_scan.owasp_iac.compliance_report }

  lifecycle {
    precondition {
      condition     = data.tfanalyze_scan.owasp_iac.high_count == 0
      error_message = "OWASP IaC compliance gate failed.\n\n${data.tfanalyze_scan.owasp_iac.compliance_report}"
    }
  }
}
```

The full worked file is at
[`examples/data-sources/tfanalyze_scan/compliance-gate.tf`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/terraform-provider/examples/data-sources/tfanalyze_scan/compliance-gate.tf).

## Schema

### Required

- `target` (String) Workspace path to scan. Absolute or relative to the
  calling module — `path.module` is the typical value.

### Optional

- `mode` (String) Scan mode. One of `static` (default), `diff`, `plan`,
  `pr-review`. The `fleet` and `trend` modes are not currently supported by
  the data source.
- `show_info` (Boolean) Include INFO-tier findings (Module Reuse advisories,
  etc.) in the output. Default `false`.
- `attack_graph` (Boolean) Build the internet → crown-jewels attack graph and
  promote critical-path findings.
- `script_path` (String) Per-data-source override for the path to `detect.py`.
  Falls back to the provider-block setting.
- `compliance_framework` (String) When set, also runs the engine's compliance
  gap report against the named framework (`cis`, `pci_dss`, `soc2`,
  `owasp_iac`, `all`) and surfaces the rendered text in `compliance_report`.
  Useful for `precondition` checks that gate on specific control coverage
  rather than just score.

### Read-Only

- `score` (Number) Workspace score, 0–100. Higher is better.
- `grade` (String) Letter grade — `A`, `B`, `B-`, `C`, `D`, or `F`.
- `scoring_version` (Number) Engine scoring formula version. Pinned so a
  downstream gate can detect a formula change.
- `total_findings` (Number) Total finding count (sum of all tiers).
- `critical_count` (Number) Number of CRITICAL-tier findings.
- `high_count` (Number) Number of HIGH-tier findings.
- `medium_count` (Number) Number of MEDIUM-tier findings.
- `low_count` (Number) Number of LOW-tier findings.
- `info_count` (Number) Number of INFO-tier findings (Module Reuse, etc.).
- `findings_json` (String) Full findings list as a JSON string. Use
  `jsondecode()` to inspect individual findings.
- `json_report` (String) Full engine JSON output (summary + findings +
  optional attack graph). `jsondecode()` to consume.
- `compliance_report` (String) Plain-text compliance gap report. Empty unless
  `compliance_framework` was set on the data source. Suitable for embedding
  in a `precondition.error_message` to fail the plan with a human-readable
  framework breakdown.
