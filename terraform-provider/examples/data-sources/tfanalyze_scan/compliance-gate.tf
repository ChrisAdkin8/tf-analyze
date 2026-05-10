# Compliance-gate worked example.
#
# Sibling to `data-source.tf` (which gates on score/finding counts).
# This file shows the second use case the provider unlocks: gating on a
# named compliance framework, with the rendered gap report pasted into
# the plan-failure message so the operator sees exactly which controls
# are failing without leaving the terminal.
#
# Frameworks: `cis`, `pci_dss`, `soc2`, `owasp_iac`, `all`. The
# `compliance_report` output is empty unless `compliance_framework` is
# set, so the same data source can drive both a score gate and a
# compliance gate when both are wanted.

terraform {
  required_providers {
    tfanalyze = {
      source = "ChrisAdkin8/tfanalyze"
    }
  }
}

provider "tfanalyze" {
  # script_path = "/path/to/detect.py"
}

# OWASP IaC Cheat Sheet gate — maps the static-analysable items from the
# OWASP Infrastructure-as-Code Security Cheat Sheet (Develop and
# Distribute / Deploy / Runtime).
data "tfanalyze_scan" "owasp_iac" {
  target               = path.module
  compliance_framework = "owasp_iac"
}

output "tfanalyze_owasp_score" {
  value = data.tfanalyze_scan.owasp_iac.score
}

output "tfanalyze_owasp_compliance" {
  value = data.tfanalyze_scan.owasp_iac.compliance_report
}

# Fail the plan when any HIGH-tier OWASP IaC finding is present, and
# surface the full rendered framework breakdown so the operator can
# triage in place. The `null_resource` is a load-bearing carrier for the
# `precondition` block — its `triggers = { report = ... }` keeps the
# resource bound to the rendered report so a state-only change in
# compliance content re-evaluates the gate.
resource "null_resource" "owasp_iac_gate" {
  triggers = {
    report = data.tfanalyze_scan.owasp_iac.compliance_report
  }

  lifecycle {
    precondition {
      condition     = data.tfanalyze_scan.owasp_iac.high_count == 0
      error_message = "OWASP IaC compliance gate failed.\n\n${data.tfanalyze_scan.owasp_iac.compliance_report}\n\nFix or suppress the failing controls before applying."
    }
  }
}
