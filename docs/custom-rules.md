# Custom rules

tf-analyze ships a 353-rule built-in catalogue, but every team has
patterns that aren't generally applicable: company-wide tagging
conventions, naming schemes, blocked module sources, vendor-specific
limits. The custom-rules system lets you ship those rules alongside
the built-ins without forking the project.

## TL;DR

```bash
# 1. Scaffold a project config + example rule
python3 scripts/detect.py --target . --init

# 2. Edit .tf-analyze-rules/CUSTOM-EXAMPLE-001.yaml

# 3. Run normally — custom rules are picked up automatically
python3 scripts/detect.py --target .
```

## Files created by `--init`

| Path                                     | Role                                   |
|------------------------------------------|----------------------------------------|
| `.tf-analyze.yaml`                       | Project config (rules dir, ignore list)|
| `.tf-analyze-rules/CUSTOM-EXAMPLE-001.yaml` | Sample rule with all schema fields  |

`.tf-analyze.yaml` looks like:

```yaml
rules_dir: .tf-analyze-rules
ignore_rules:
  - OPS-AWS-TAGS-001    # we use provider default_tags everywhere
thresholds:
  fail_on: HIGH
```

## Worked example: company-wide cost-center tag

Your platform team mandates `cost_center` on every AWS resource that
supports tags. The built-in `OPS-AWS-TAGS-001` only checks for the
generic AWS-recommended set; here's a custom rule that enforces your
specific tag.

`.tf-analyze-rules/CUSTOM-COSTCENTER-001.yaml`:

```yaml
id: CUSTOM-COSTCENTER-001
title: "AWS resource missing cost_center tag"
section: ops
default_urgency: MEDIUM
blast_radius: single-resource
status: active
patterns:
  - kind: resource_missing_arg
    resource: aws_instance
    nested_path: tags.cost_center
    description: "EC2 instance missing required cost_center tag"
  - kind: resource_missing_arg
    resource: aws_s3_bucket
    nested_path: tags.cost_center
    description: "S3 bucket missing required cost_center tag"
  - kind: resource_missing_arg
    resource: aws_dynamodb_table
    nested_path: tags.cost_center
    description: "DynamoDB table missing required cost_center tag"
recommendation: |
  Add `cost_center = "<your-cc>"` to every resource's `tags` block,
  or set it once via the provider's `default_tags` block:

      provider "aws" {
        default_tags {
          tags = {
            cost_center = "platform-12345"
          }
        }
      }
verification: |
  Run `aws resourcegroupstaggingapi get-resources --tag-filters
    Key=cost_center,Values=*` and confirm every resource appears.
fix_hcl: |
  resource "aws_instance" "example" {
    tags = {
      cost_center = "platform-12345"
    }
  }
fix_disruption: none
fixtures: []
```

Run:

```bash
python3 scripts/detect.py --target . --explain CUSTOM-COSTCENTER-001
python3 scripts/detect.py --target .
```

## Schema reference

Custom rules use the same schema as the built-in catalogue. Required
fields:

| Field             | Type         | Notes                                              |
|-------------------|--------------|----------------------------------------------------|
| `id`              | string       | Must start with `CUSTOM-`. Other prefixes rejected.|
| `title`           | string       | One-line summary                                   |
| `section`         | enum         | One of `security`, `robustness`, `dry`, `style`, `simplicity`, `ops`, `cicd`, `module`, `stack`, `verification` |
| `default_urgency` | enum         | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`        |
| `blast_radius`    | enum         | `single-resource`, `module`, `environment`, `infrastructure-wide` |
| `patterns`        | list         | Pattern definitions; see kinds below               |
| `recommendation`  | string       | What to do about it                                |
| `verification`    | string       | How to verify the fix                              |

Optional fields: `cis`, `pci_dss`, `soc2_cc`, `owasp_iac`, `mitre`,
`fix_hcl`, `fix_disruption`, `fixtures`, `test_template`, `related`,
`status`. The `owasp_iac` field maps the rule to the [OWASP IaC
Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html);
each entry is `<Section> / <Item label>` with section ∈ `{Develop and
Distribute, Deploy, Runtime}`.

## Pattern kinds

The most useful kinds for custom rules:

| Kind                  | What it matches                                                       |
|-----------------------|-----------------------------------------------------------------------|
| `resource_arg`        | A resource has `arg = <regex>` (or `not_regex`)                       |
| `resource_missing_arg`| A resource lacks `arg` or nested path `outer.inner`                   |
| `resource_present`    | A resource of this type exists at all                                 |
| `resource_absent`     | NO resource of this type exists in the corpus                         |
| `hcl_attr`            | A resource attribute equals (or doesn't equal) a specific value       |
| `grep`                | Plain-text regex search (each pattern records why in `text_scan:`). `code_only: true` ignores comments and heredoc text (use it for rules about Terraform structure); `hcl_context: true` ignores comments only (use it when heredoc text matters, e.g. secrets) |
| `firewall_open_port`  | An inbound allow rule open to the internet (`0.0.0.0/0`, `::/0`; Azure `*` / `Internet`), optionally only on `ports:` — `resource:` one of `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, `azurerm_network_security_group`, `azurerm_network_security_rule`, `google_compute_firewall` (default). Egress / deny / outbound rules never match; `var.X` sources are resolved |
| `iam_policy_analysis` | Walk `data.aws_iam_policy_document` statements (see below)            |
| `high_entropy_string` | A string literal whose Shannon entropy marks it a probable hardcoded secret (any arg name) — complements the name-based secret greps |
| `policy`              | Cross-resource / conditional / aggregate predicate — see the [policy DSL guide](policy-dsl.md) |

### How `arg` and `nested_path` match (`resource_missing_arg`)

- **`arg` is top-level.** `arg: retention_in_days` is satisfied only by
  the resource's own `retention_in_days = ...` (or `retention_in_days {`
  block). The same name inside a nested block, as a key of a map such as
  `tags`, or inside a string, heredoc or comment does **not** count.
- **`nested_path` walks into blocks and maps.** Each segment after the
  first can be a nested block (`settings { ... }`), a map attribute
  (`tags = { ... }`), or a list of objects (`ingress = [{ ... }]`). So
  `tags.cost_center` is satisfied by `tags = { cost_center = "..." }`.
- **Repeated blocks need every copy.** If a segment is a block that
  appears more than once, *every* copy must have the rest of the path.
  Set `instances: any` on the pattern when one copy is enough — e.g.
  `SEC-AWS-WAF-002` (`rule.statement.rate_based_statement` with
  `instances: any`: one rate-based rule among a web ACL's rules is fine).
- `dynamic "X" { content { ... } }` counts as an `X` block.

### How values are matched (`resource_arg`, `hcl_attr`)

- The value is looked up at `nested_path` if set, else at `arg`; either
  may be dotted (`arg: metadata_options.http_tokens`). Lookups are
  top-level and walk blocks and maps exactly as above.
- The value your `regex` / `not_regex` sees is HCL text: strings without
  their quotes (`"allow-all"` → `allow-all`), references bare
  (`var.x`), booleans as `true` / `false`, lists and maps in HCL syntax
  with quoted strings (`["0.0.0.0/0", var.z]`). Plan / state mode
  (`--plan-json`, `--mode drift`) renders resolved values the same way.
- Through a repeated block the rule fires if **any** copy's value
  matches; `fire_if_absent: true` also fires if any copy lacks the value.
- `resource_body_contains` regexes don't see comments or heredoc bodies,
  so commented-out code and inline scripts / policy documents can't
  match. Ordinary quoted strings are still searched.

These rules are evaluated on the parsed HCL tree, or — for a file the
parser can't read — by a text fallback that follows the same rules.

Rules can raise a finding's urgency with `escalation:` — a structured
`match:` (e.g. `ports:` for `firewall_open_port`, or an attribute path →
regex) is evaluated by the engine; see
[`catalog/README.md`](../catalog/README.md#escalation-semantics).

Pattern kinds support these suppression mechanisms:

- `suppress_if: { arg: <name>, equals: <value> }` — resource_arg / resource_missing_arg
- `suppress_if_body_contains: '<substring>'` — resource_arg / resource_missing_arg / hcl_attr
- `unless_repo_has: <resource type>` — resource_arg / resource_missing_arg: skip when a
  resource of that type (not `enabled = false`) is anywhere in the scan, e.g. an
  account-level `aws_ebs_encryption_by_default`

See [`SKILL.md`](../SKILL.md) for the full catalogue of pattern kinds
and engine semantics, and the [policy DSL guide](policy-dsl.md) for the
`kind: policy` predicate language (cross-resource / conditional / aggregate).

## Suppressing built-in rules

`.tf-analyze.yaml`:

```yaml
ignore_rules:
  - OPS-AWS-TAGS-001
  - SEC-AWS-IAM-USER-001
```

Combines with inline `# tf-analyze:ignore <ID>` comments and
`.tf-analyze-ignore.yaml`. Project-level ignores apply
*before* the per-file inline ones; both contribute to
`suppressed:` in the JSON output.

## Testing custom rules

Custom rules support the same fixture-based testing as built-ins.
Drop a directory under `fixtures/<rule-id>/main.tf` with a positive
example, and a `fixtures/<rule-id>_clean/main.tf` with a clean
example. Then:

```bash
python3 -m pytest tests/test_fixtures.py tests/test_clean_fixtures.py -k CUSTOM
```

You'll need to add a wrapper that points pytest at your project's
custom rules directory; see `tests/test_custom_rules.py` for the
pattern.

## Caveats

- Rule IDs must be globally unique. If a custom rule shadows a
  built-in (same ID), the loader prints a warning and keeps the
  built-in.
- Each pattern runs under a time budget (5 s per pattern per file;
  `TF_ANALYZE_PATTERN_TIMEOUT` overrides it, `0` turns it off). A regex
  that backtracks catastrophically — nested quantifiers such as `(a+)+`,
  or alternatives that can match the same text — is stopped there,
  reported under `summary.rule_timeouts`, and fails `--fail-on`, since a
  check that did not finish has not passed. Enforced on Unix; not on
  Windows.
- Custom rules don't get auto-MITRE/CIS mappings. Add them by hand if
  you want them surfaced in `--format mitre` / `--format compliance`.
- The Run Task server (`integrations/run-task/`) does NOT pick up
  custom rules unless you bake `.tf-analyze-rules/` into the Docker
  image — by design, since the server is meant to be a
  org-controlled gate, not a per-team customizer.
