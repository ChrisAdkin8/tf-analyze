# Expected findings:
#  - SEC-DATASOURCE-001 MEDIUM — data.external runs shell script
#  - SEC-DATASOURCE-001 MEDIUM — data.http fetches URL at plan time

data "external" "env_info" {
  program = ["bash", "-c", "echo '{\"hostname\": \"'$(hostname)'\"}'"]
}

data "http" "config" {
  url = "https://example.com/config.json"
}

output "hostname" {
  value = data.external.env_info.result["hostname"]
}
