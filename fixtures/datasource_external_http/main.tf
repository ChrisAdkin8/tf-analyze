# Expected findings:
#  - SEC-DATASOURCE-003 HIGH — data "external" plan-time exec
#  - SEC-DATASOURCE-003 HIGH — data "http" plan-time fetch

data "external" "secret_fetcher" {
  program = ["bash", "${path.module}/fetch.sh"]
}

data "http" "remote_cidr_list" {
  url = "https://example.com/cidrs.json"
}
