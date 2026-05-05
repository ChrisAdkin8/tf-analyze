# Expected findings:
#  - SEC-PROVISIONER-001 HIGH — local-exec provisioner
#  - SEC-PROVISIONER-001 HIGH — remote-exec provisioner

resource "null_resource" "bootstrap" {
  provisioner "local-exec" {
    command = "echo 'bootstrapping...'"
  }
}

resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y nginx",
    ]
  }
}
