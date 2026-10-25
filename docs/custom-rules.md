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
| `grep`                | Plain-text regex search                                               |
| `iam_policy_analysis` | Walk `data.aws_iam_policy_document` statements (see below)            |
| `policy`              | Cross-resource / conditional / aggregate predicate — see the [policy DSL guide](policy-dsl.md) |

Pattern kinds support these suppression mechanisms:

- `suppress_if: { arg: <name>, equals: <value> }` — resource_arg / resource_missing_arg
- `suppress_if_body_contains: '<substring>'` — resource_arg / resource_missing_arg / hcl_attr

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
- Custom rules don't get auto-MITRE/CIS mappings. Add them by hand if
  you want them surfaced in `--format mitre` / `--format compliance`.
- The Run Task server (`integrations/run-task/`) does NOT pick up
  custom rules unless you bake `.tf-analyze-rules/` into the Docker
  image — by design, since the server is meant to be a
  org-controlled gate, not a per-team customizer.
