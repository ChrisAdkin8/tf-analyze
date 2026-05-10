---
page_title: "tfanalyze Provider"
description: |-
  Run the tf-analyze static-analysis engine at plan time and gate `terraform apply` on a clean scan via `precondition` blocks — without external CI infrastructure.
---

# tfanalyze Provider

[`tf-analyze`](https://github.com/ChrisAdkin8/tf-analyze) is a static-analysis
engine for Terraform code: it walks the HCL, applies a 217-rule catalogue, and
returns a score (0–100), a letter grade, per-tier finding counts, and an
optional attack-graph rendering. The provider's single `tfanalyze_scan` data
source surfaces all of that to a Terraform configuration so plans and applies
can be gated on a clean scan via `precondition` blocks — no GitHub Action, no
out-of-band CI, no extra credentials.

## Example Usage

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

data "tfanalyze_scan" "this" {
  target = path.module
}

resource "null_resource" "gate" {
  triggers = { score = data.tfanalyze_scan.this.score }

  lifecycle {
    precondition {
      condition     = data.tfanalyze_scan.this.high_count == 0 && data.tfanalyze_scan.this.critical_count == 0
      error_message = "tf-analyze: ${data.tfanalyze_scan.this.critical_count} CRITICAL · ${data.tfanalyze_scan.this.high_count} HIGH findings present. Fix or suppress before applying."
    }
  }
}
```

A second worked example under
[`examples/data-sources/tfanalyze_scan/compliance-gate.tf`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/terraform-provider/examples/data-sources/tfanalyze_scan/compliance-gate.tf)
shows how to gate on a specific compliance framework (CIS / PCI-DSS / SOC 2 /
OWASP IaC) and surface the rendered gap report directly in the plan failure
message.

## Schema

### Optional

- `engine_command` (String) Executable used to run the engine. Defaults to
  `python3`.
- `script_path` (String) Absolute path to `detect.py`. Defaults to
  `$TFA_DETECT_PY` if set, else `~/.tf-analyze/scripts/detect.py`. The
  `script_path` argument on the data source overrides this.

## Engine setup

The provider shells out to `detect.py`; it does not bundle the engine. Install
the engine once per machine:

```sh
git clone https://github.com/ChrisAdkin8/tf-analyze.git ~/.tf-analyze
export TFA_DETECT_PY="$HOME/.tf-analyze/scripts/detect.py"
```

Or wire `script_path` explicitly. The data source surfaces a clear diagnostic
when neither is set.

## Why a provider (and not just a GitHub Action)

The Action runs in CI; the provider runs at `terraform plan` and `terraform
apply` time. That means a developer running `terraform apply` from a laptop
gets the same gate the CI gets, without out-of-band tooling. The provider also
returns the full engine JSON (`json_report`), so you can drive richer logic
from the same scan — choose a `count` based on the score, fan out a `for_each`
over critical findings, or paste the rendered compliance report into a
plan-failure message.
