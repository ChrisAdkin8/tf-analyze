# Policy-as-code DSL (`kind: policy`)

Write **cross-resource, conditional, and aggregate** rules as catalogue data —
the things the pattern kinds (`grep`, `resource_arg`, `resource_missing_arg`, …)
can't express because they only see one resource at a time. A policy rule is a
small predicate over the parsed resource model; a violation becomes a normal
finding with a stable ID, urgency, risk-score weight, SARIF output, compliance
mapping, and `# tf-analyze:ignore` suppression — exactly like any other rule.

No new dependency: the evaluator is a hand-rolled parser (no `eval`, safe on
`--catalog` user files) and runs on the existing parser.

## When to reach for it

| Use a pattern kind when… | Use `kind: policy` when… |
|---|---|
| the check is one attribute on one resource | the check spans **two resources** ("bucket → its logging config") |
| presence/absence of an arg | a **condition** drives the requirement ("if tagged prod, then …") |
| a regex on the block | an **aggregate** ("at most N of …", "none of …") |

## Rule schema

A policy rule is an ordinary catalogue entry whose pattern has `kind: policy`:

```yaml
id: ORG-S3-LOGGING-001
title: "S3 bucket without access logging"
section: security
default_urgency: MEDIUM
blast_radius: single-resource
status: active
cwe: ["CWE-778"]
recommendation: |
  Add an aws_s3_bucket_logging resource targeting the bucket.
verification: |
  terraform state list | grep aws_s3_bucket_logging
patterns:
  - kind: policy
    match:   'resource.type == "aws_s3_bucket"'
    require: 'exists(aws_s3_bucket_logging where that.attr.bucket matches resource.name)'
    description: "S3 bucket {resource.name} has no aws_s3_bucket_logging"
```

Pattern fields:

- **`match`** *(required)* — selects which resources the rule binds.
- **`require` / `forbid`** *(exactly one)* — the assertion. `require` fires a
  finding when it's **false**; `forbid` fires when it's **true**.
- **`description`** — the finding text. `{resource.<path>}` is interpolated.

All the entry-level metadata (`id`, `default_urgency`, `cwe`, `mitre`,
`fix_hcl`, `applies_when`, compliance tags…) works unchanged.

## Data model

A rule sees the resource bound by `match` as `resource`, and (inside
quantifiers) each candidate as `that`:

```
resource.type        "aws_s3_bucket"
resource.name        "data"
resource.address     "aws_s3_bucket.data"
resource.file / .line
resource.attr.<path> attribute value, or null if absent
                     (nested blocks descend: resource.attr.ingress.from_port)
resource.tags.<key>  a tags = { … } / labels = { … } map value, or null
```

## Grammar

```
and  or  not                       boolean
== != < <= > >= in "not in"        comparisons
matches                            regex search (author supplies anchors: "^aws_")
has(path)                          path resolves to a non-null value
exists(TYPE where PRED)            any resource of TYPE satisfies PRED
none(TYPE where PRED)              no resource of TYPE satisfies PRED
all(TYPE where P : Q)              every TYPE matching P also satisfies Q
count(TYPE where PRED)             a number, used in a comparison
( … )  "str"  123  true  false  null  ["a", "b"]
```

## Worked examples

```yaml
# conditional — prod databases must block deletion
match:   'resource.type == "aws_db_instance" and resource.tags.Environment == "prod"'
require: 'resource.attr.deletion_protection == true and resource.attr.skip_final_snapshot != true'
```
```yaml
# aggregate — no SSH open to the world (`in` is VALUE in LIST)
match:   'resource.type == "aws_security_group"'
forbid:  '"0.0.0.0/0" in resource.attr.ingress.cidr_blocks
          and resource.attr.ingress.from_port <= 22 and resource.attr.ingress.to_port >= 22'
```
```yaml
# org guardrail — every aws_ resource must carry a CostCenter tag
match:   'resource.type matches "^aws_"'
require: 'has(resource.tags.CostCenter)'
```

## v1 limitations (read before authoring)

v1 resolves `resource.attr.*` / `resource.tags.*` with the regex parser, with
best-effort coercion (numeric strings → numbers, `true`/`false` → bool,
`[ … ]` → list). Consequences:

- **Repeated blocks** (several `ingress {}`) currently bind to the *first* one.
- **Computed values** aren't evaluated — `from_port = var.ssh_port` is the
  unresolved reference, not `22` (only declared `variable` defaults are folded
  in). For resolved values, run the rule against `--plan-json`.
- **Cross-resource references** are matched with `matches` (regex) so the
  `.id`/`.arn` suffix doesn't matter — see the S3 example.
- **Graph predicates** (`reaches`, `is_crown_jewel`) are **phase 2** —
  `resource.graph.*` is `null` in v1.

A future hcl2-backed attribute accessor (`tasks/policy-dsl-draft.md` §6, "Scope
A") removes the first two limitations without changing the grammar.

## Validation

Policy expressions are compile-checked when the catalogue loads: a syntax error
surfaces under `--strict-catalog` (and the strict-load test) instead of a rule
that silently never fires. A malformed expression at scan time is inert (no
finding, no crash) rather than aborting the scan.
