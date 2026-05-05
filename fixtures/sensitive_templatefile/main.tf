# Expected findings:
#  - SEC-SENSITIVE-003 HIGH — sensitive variable passed to templatefile()

variable "db_password" {
  type      = string
  sensitive = true
}

resource "local_file" "config" {
  filename = "/tmp/config.yml"
  content  = templatefile("${path.module}/config.tpl", {
    password = var.db_password
  })
}
