## `--apply-fixes` keeps fixes inside one-line blocks, and skips more example values

- **One-line blocks**: on a block whose closing `}` shares a line with
  other code (`resource "aws_db_instance" "db" {}`, or
  `{ engine = "mysql" }`), `--apply-fixes` inserted the missing arguments
  *above* the `resource` line, outside the block. The file no longer
  parsed, and every re-run added the lines again. Such a block is now
  split so its `{` ends a line and its `}` sits on a line of its own, and
  only when a fix then changes it.
- **Example values**: nine more rules had a `fix_hcl` whose values a
  person has to choose, and `--apply-fixes` pasted them. They are now
  `fix_hcl_example: true`:
  - `SEC-AZURE-SQL-002` replaced `start_ip_address` with the
    documentation IP `203.0.113.10` and left `end_ip_address =
    "255.255.255.255"`, so the firewall stayed open.
  - `SEC-AZURE-FED-IDENTITY-001` replaced the trust `subject` with
    `repo:my-org/my-repo:...`, breaking the user's CI sign-in.
  - `SEC-AZURE-RBAC-001` and `SEC-GCP-IAM-002` pointed at `example`
    resources that don't exist. `SEC-GCP-IAM-001` swapped any admin role
    for `roles/storage.objectViewer`.
  - `STK-AWS-LAMBDA-001` and `STK-GCP-FUNCTIONS-001` set a Python
    runtime whatever the function's language. `STK-AZURE-MYSQL-EOL-001`
    and `STK-AWS-RDS-004` wrote a PostgreSQL version into MySQL servers.
