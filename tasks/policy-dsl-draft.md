# Policy-as-code DSL — design draft

> **STATUS: DRAFT / NOT IMPLEMENTED.** A design for review, not shipped behaviour.
> Closes the audit's #1 capability gap (cross-resource / conditional custom rules).
> Goal of this doc: agree the authoring experience + data model before any code.

## 1. Problem

Every custom rule today is single-resource and pattern-based (`grep`,
`resource_arg`, `resource_missing_arg`, `resource_body_contains`, `hcl_attr`,
…). They match a regex or an attribute *inside one resource*. Anything that
needs **cross-resource relationships, conditionals, or aggregates** can only be
written as a Python handler (the engine's own `graph_check` / `intent_gap` /
`cross_module` rules live in `_cross_resource.py` and are not author-editable).
Every serious competitor (Checkov, Trivy/tfsec, KICS, Snyk, Sentinel) lets users
express these as data — it's the gating factor for org-wide standardisation.

## 2. Goals / non-goals

**Goals**
- Author cross-resource, conditional, and aggregate rules as **YAML data**, no Python.
- Reuse the resource model + dependency/attack graph the engine **already builds**.
- Plug into the existing catalogue + finding pipeline so policy rules get an ID,
  urgency, risk-score weight, SARIF, PR-summary, compliance mapping, `fix_hcl`,
  and `# tf-analyze:ignore` suppression **for free**.
- Stay **stdlib-only / single-binary** — no OPA/Rego/Go/WASM dependency.

**Non-goals (explicit)**
- Not Turing-complete. No loops, no user-defined functions, no mutation, no I/O.
- Not Rego-compatible — existing Rego libraries won't port (deliberate trade-off
  to keep the no-pip identity; closes ~80% of the gap).
- The expression evaluator is a **custom safe parser**, never Python `eval()` —
  `--catalog` accepts user files, so arbitrary-code-from-YAML is a non-starter.

## 3. Data model exposed to a rule

Maps 1:1 onto what the engine already computes (`_build_resource_index`,
`build_attack_graph`). A rule sees:

```
resource                      # the resource currently bound by `match`
  .type      "aws_s3_bucket"
  .name      "data"
  .address   "aws_s3_bucket.data"  (module-prefixed when nested)
  .file / .line
  .attr.<dotted.path>         parsed attribute value, or null if absent
                              (e.g. resource.attr.server_side_encryption_configuration.rule)
  .tags.<key>                 merged tags/labels, or null
  .graph.internet_reachable   bool   ┐ present when --attack-graph data exists,
  .graph.is_crown_jewel       bool   │ else null (rule self-skips — see §6)
  .graph.on_critical_path     bool   ┘

<TYPE>                        # a resource collection, e.g. aws_kms_key
                              used only inside quantifiers (§4); the candidate
                              is bound as `that` (same attribute surface as resource)
```

Resolved variable defaults / locals are already folded in by
`_extract_var_defaults_by_dir`, so `resource.attr.x` sees `var.x`'s default.

## 4. Grammar

Expressions are **strings** in a small language (CEL/Rego-ish — more readable for
authors than a nested-YAML AST). EBNF-ish:

```
expr      := orExpr
orExpr    := andExpr ("or" andExpr)*
andExpr   := notExpr ("and" notExpr)*
notExpr   := "not" notExpr | comparison
comparison:= operand ( ("==" | "!=" | "<" | "<=" | ">" | ">=" | "in" | "not in"
                        | "matches") operand )?
operand   := literal | path | quantifier | graphFn | "(" expr ")"
path      := ("resource" | "that") ("." IDENT)+          # null on missing segment
literal   := STRING | NUMBER | "true" | "false" | "null" | "[" listItems "]"
quantifier:= ("exists" | "all" | "none") "(" TYPE ["where" expr] [":" expr] ")"
           | "count" "(" TYPE ["where" expr] ")"          # yields a number
graphFn   := "reaches" "(" "resource" "," TYPE ["where" expr] ")"   # graph path exists
           | "references" "(" "resource" "," "that" ")"            # HCL ref edge
           | "depends_on" "(" "resource" "," TYPE ["where" expr] ")"
```

Semantics of the quantifiers (the cross-resource core):
- `exists(T where P)` → true if **any** resource of type `T` satisfies `P`
  (`P` may reference both `resource.*` and `that.*`).
- `all(T where P : Q)` → for **every** `T` matching `P`, `Q` holds.
- `none(T where P)` → no `T` matches `P`.
- `count(T where P)` → integer, used in a comparison (`count(...) <= 0`).
- `matches` is anchored-regex on a string operand. Missing path = `null`;
  comparisons with `null` are false (so absent attrs don't accidentally pass).

## 5. Rule schema

A new pattern `kind: policy`, reusing all existing entry-level metadata:

```yaml
id: ORG-S3-LOGGING-001
title: "S3 bucket without access logging"
section: security
default_urgency: HIGH
cwe: ["CWE-778"]
mitre: ["T1530"]
fix_hcl: |
  resource "aws_s3_bucket_logging" "<name>" { bucket = aws_s3_bucket.<name>.id ... }
applies_when:                 # existing gating still works
  min_provider: { aws: "4.0" }
patterns:
  - kind: policy
    match:   'resource.type == "aws_s3_bucket"'
    require: 'exists(aws_s3_bucket_logging where that.attr.bucket == resource.name)'
    description: "S3 bucket {resource.name} has no aws_s3_bucket_logging referencing it"
fixtures: [org_s3_logging_dirty]
```

- `match` (selector): which resources the rule binds. Required.
- `require` / `forbid`: exactly one. `require` fires when its expr is **false**;
  `forbid` fires when **true**.
- `description`: finding text; supports `{resource.<path>}` interpolation.

## 6. Evaluation & pipeline integration

Registered as a **corpus handler** (`_CORPUS_HANDLERS["policy"]`) so it has the
workspace-wide `resource_index_cache` + the graph the cross-resource handlers
already use. Per (entry × pattern):

1. Parse `match` + `require`/`forbid` once (cached AST per pattern).
2. For each resource in the index: bind `resource`, eval `match`; if true, eval
   the assertion; on violation emit a normal finding at `resource.file:line` with
   the entry's `id`/`urgency`/`cwe`/… and the interpolated `description`.
3. Findings then flow through the **existing** dedup → suppression → scoring →
   SARIF/compliance/PR-summary/`fix_hcl` path unchanged.

Graph predicates self-skip (no finding, no error) when graph data is absent —
the engine only builds it under `--attack-graph`; document that graph rules need
that flag, mirroring how `blast_radius` surfaces already behave.

`_catalog.validate_catalog_entry` gains a `kind: policy` branch: parse the
expressions at load time and reject syntax errors (so `--strict-catalog` and the
new strict-load test catch a broken policy instead of silently never firing).

### Where `resource.attr` comes from — build through the canonical index

`resource.attr.<path>` needs a **structured, typed parse** (a `python-hcl2`-backed
accessor with a regex fallback — "Scope A" in the parsing analysis; see §9). The
engine already has a canonical resource representation: `_build_resource_index`
(`<type>.<name>` → `{file, line, body, type, name}`), consumed by `graph_check`
and `build_attack_graph`. **Enrich that index rather than introduce a parallel
DSL-only model** — there are already two representations (per-file
`InFileCtx.resources` and the workspace index); a third is pure debt. The
following refactors are *additive / behaviour-neutral* and should be done as part
of Scope A (they're the model-building the DSL needs anyway, done in the right place):

1. **Add a typed `attrs` accessor** to each index entry — hcl2 tree when present,
   regex fallback otherwise. The DSL reads `attrs`; existing consumers keep reading
   `body`/`type`/`name` unchanged → low fixture risk.
2. **Build the index once.** It is currently built twice (`detect.py:728` for
   corpus handlers, `detect.py:2780` for the attack graph); the DSL would make it
   three. Consolidate to one cached build.
3. **Centralise the hcl2-vs-regex choice** behind that accessor, replacing the
   inline `_USE_HCL2 and "<<" in body` check in `block_arg_value`. The evaluator
   stays parser-agnostic; the fallback lives in one place.
4. **A parse-once `FileModel` seam** (text → `{tree, body, line-index}`) that the
   index populates — cheap to design now, and the exact hook an engine-wide
   hcl2-primary switch (Scope B) would later swap into instead of rewriting.

Out of scope here (that's Scope B): re-backing the ~80 `find_blocks` /
`block_arg_value` call sites, or migrating the in-file handlers onto the index.
Keep that firewall so Scope A stays additive and suite-gated.

## 7. Worked examples

```yaml
# (a) Cross-resource — RDS must use a customer-managed KMS key with rotation
match:   'resource.type == "aws_db_instance"'
require: 'exists(aws_kms_key where that.address == resource.attr.kms_key_id
                 and that.attr.enable_key_rotation == true)'
```
```yaml
# (b) Conditional — prod databases must block deletion
match:   'resource.type == "aws_db_instance" and resource.tags.Environment == "prod"'
require: 'resource.attr.deletion_protection == true
          and resource.attr.skip_final_snapshot != true'
```
```yaml
# (c) Aggregate — no SSH open to the world
match:   'resource.type == "aws_security_group"'
forbid:  'resource.attr.ingress.cidr_blocks in ["0.0.0.0/0"]
          and resource.attr.ingress.from_port <= 22 and resource.attr.ingress.to_port >= 22'
```
```yaml
# (d) Graph — an internet-reachable resource must not reach a crown jewel
#     without an intervening WAF  (requires --attack-graph)
match:   'resource.graph.internet_reachable == true'
forbid:  'reaches(resource, aws_db_instance where that.graph.is_crown_jewel == true)
          and not exists(aws_wafv2_web_acl)'
```
```yaml
# (e) Org guardrail — every resource must carry a CostCenter tag
match:   'resource.type matches "^aws_"'
require: 'has(resource.tags.CostCenter)'
```

## 8. Phasing

- **v1** — `match` + single-resource conditionals + `exists`/`count`/`all`/`none`
  over the resource index (examples a–c, e). No graph functions. Covers the
  majority of org-guardrail asks.
- **v2** — graph functions (`reaches`/`depends_on`/`references`, example d), gated
  on `--attack-graph` data.
- **v3** — convenience: list/map comprehensions on attrs (`ingress` is repeatable),
  `--explain` rendering of a policy, an authoring linter.

## 9. Risks / open questions

- **Performance.** Cross-resource `exists` is O(resources²) naïvely; bind by the
  resource index (already keyed by type) and short-circuit. Cap or warn on very
  large corpora. Benchmark against `tests/test_perf.py`'s budget.
- **Repeatable / nested HCL** (`ingress {}` blocks, dynamic blocks) — how does
  `resource.attr.ingress.from_port` bind when there are several `ingress`? v1:
  define it as "any block matches"; document explicitly. This is the thorniest
  modelling question and should be pinned before build.
- **Safe evaluator** — recursive-descent parser + tree-walking evaluator over a
  fixed operator/function set; property-test it `never_raises` on arbitrary YAML
  (same discipline as `brace_walk`). No `eval`, no attribute access into Python objects.
- **Attribute resolution fidelity** — `resource.attr.x` relies on the existing
  (regex/hcl2) extraction, which has known multi-line gaps; the DSL inherits
  whatever the parser resolves. The recent `brace_walk`/`block_arg_value` fixes
  help; full fidelity argues for the `python-hcl2`-primary path (separate item).
- **Author errors** — a typo'd type in `exists(aws_kms_keys …)` silently never
  matches → no finding. Mitigate: validate referenced types against a known-type
  list at load (warn, don't fail).

## 10. Effort

**v1 DSL: Medium, ~4–5 days** — and this *includes* the Scope-A parsing work
(the model-building is shared, not additive on top):

- **Expression parser + evaluator** — ~1–2 days incl. fuzz tests. The
  load-bearing, highest-risk piece; prototype it first against §7.
- **Scope-A resource model** — ~1 day. The typed `attrs` accessor built *as* the
  canonical-index enrichment + parse-once seam (§6). Additive / behaviour-neutral,
  gated by the existing 1189-test suite.
- **`policy` corpus handler + finding emission** — ~1 day.
- **`_catalog` validation + strict-load coverage** — ~0.5 day.
- **Docs + a worked rule-pack + fixtures** — ~1 day.
- **v2 graph functions** add ~1 day on top.

Scope A is *not a prerequisite* for v1 — conditionals/cross-resource/graph all
work on the current `body`-only index; only deep nested-attr predicates need it.
A v1 could ship on the regex model and add the typed accessor later.

**Engine-wide `hcl2`-primary (Scope B) is a separate ~1–2 week initiative**,
dominated by reconciling the 609 fixture/clean tests + line-number handling, plus
permanent dual-path maintenance. Explicitly **not** bundled with the DSL; the §6
parse-once seam is precisely what lets B become a swap rather than a rewrite.
