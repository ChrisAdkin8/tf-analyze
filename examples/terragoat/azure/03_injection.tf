# OWASP A03:2021 — Injection
# Cloud: Azure
#
# Azure-shaped injection vectors:
#
#   1. `azurerm_linux_virtual_machine.custom_data` (and the older
#      `aws-ish` shape on Windows) constructed from unvalidated
#      tfvars — runs as root at first boot via cloud-init.
#   2. `null_resource` provisioner shelling out to az CLI with
#      interpolated tfvars.
#   3. Function App application settings forwarded to a downstream
#      shell.
#
# Real-world impact: the same shape as on AWS / GCP. An attacker
# who controls a tfvar gets RCE on the VM.
#
# Expected tf-analyze findings:
#   - SEC-PROVISIONER-001  HIGH   Provisioner block used for shell execution
#
# Fix summary: keep cloud-init scripts out of unvalidated tfvar paths;
# use `validation { condition = ... }` blocks on variables; for
# provisioners, route through a known-safe wrapper script that takes
# typed CLI args, not interpolated strings.

variable "vm_name" {
  description = "VM name (used in the cloud-init shell)"
  type        = string
}

# custom_data is base64-encoded but the source is interpolated
# tfvars unsanitised. Whatever the tfvar contains lands in bash -c.
resource "azurerm_linux_virtual_machine" "user_data_inject" {
  name                  = "demo-userdata-inject"
  resource_group_name   = azurerm_resource_group.demo.name
  location              = azurerm_resource_group.demo.location
  size                  = "Standard_B1s"
  admin_username        = "azureuser"
  network_interface_ids = []

  custom_data = base64encode(<<-EOT
    #!/bin/bash
    /opt/setup ${var.vm_name}
  EOT
  )

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  admin_ssh_key {
    username   = "azureuser"
    public_key = "ssh-rsa AAAA..."
  }
}

resource "null_resource" "az_cli_inject" {
  provisioner "local-exec" {
    command = "az vm show --name ${var.vm_name} --resource-group demo-rg"
  }
}
