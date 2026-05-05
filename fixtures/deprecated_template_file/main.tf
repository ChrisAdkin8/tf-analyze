# Expected findings:
#  - STK-DEPRECATION-002 MEDIUM — data.template_file is deprecated; use templatefile()

data "template_file" "init" {
  template = "Hello, $${name}!"
  vars = {
    name = "world"
  }
}

output "rendered" {
  value = data.template_file.init.rendered
}
