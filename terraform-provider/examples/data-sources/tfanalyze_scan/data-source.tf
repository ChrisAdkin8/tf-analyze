# Worked example: gate `terraform apply` on a clean tf-analyze scan.
#
# `data "tfanalyze_scan"` runs the engine at plan time and surfaces the
# score / grade / counts. A `precondition` block fails the plan when
# the score drops below the threshold — without external CI.

terraform {
  required_providers {
    tfanalyze = {
      source = "ChrisAdkin8/tfanalyze"
    }
  }
}

provider "tfanalyze" {
  # Defaults: $TFA_DETECT_PY then ~/.tf-analyze/scripts/detect.py.
  # Set explicitly when running outside the standard install layout.
  # script_path = "/path/to/detect.py"
}

data "tfanalyze_scan" "this" {
  target       = path.module
  mode         = "static"   # or "diff" / "plan" / "pr-review"
  attack_graph = true
}

# Print the headline numbers to stdout so the operator sees the gate
# decision without parsing JSON.
output "tfanalyze_score" { value = data.tfanalyze_scan.this.score }
output "tfanalyze_grade" { value = data.tfanalyze_scan.this.grade }

resource "null_resource" "gate" {
  triggers = {
    score = data.tfanalyze_scan.this.score
  }

  lifecycle {
    precondition {
      condition     = data.tfanalyze_scan.this.high_count == 0 && data.tfanalyze_scan.this.critical_count == 0
      error_message = "tf-analyze: ${data.tfanalyze_scan.this.critical_count} CRITICAL · ${data.tfanalyze_scan.this.high_count} HIGH findings present. Fix or suppress before applying."
    }
  }
}
