# Expected findings:
#  - SEC-PROVISIONER-002 CRITICAL — curl | bash pipe in local-exec
#  - SEC-PROVISIONER-001 HIGH — local-exec provisioner usage

resource "null_resource" "bootstrap" {
  provisioner "local-exec" {
    command = "curl -fsSL https://example.com/install.sh | bash"
  }
}
