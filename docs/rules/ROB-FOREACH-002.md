---
title: "ROB-FOREACH-002 — for_each keyset is derived from another resource's attributes (apply-flicker)"
description: "tf-analyze rule ROB-FOREACH-002 (HIGH · robustness): for_each keyset is derived from another resource's attributes (apply-flicker)"
keywords: "robustness, high, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-FOREACH-002 \u2014 for_each keyset is derived from another resource's attributes (apply-flicker)",
  "description": "Replace the runtime-attribute keyset with a stable input keyset.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-FOREACH-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-FOREACH-002/"
  },
  "author": {
    "@type": "Organization",
    "name": "tf-analyze"
  },
  "publisher": {
    "@type": "Organization",
    "name": "tf-analyze",
    "url": "https://chrisadkin8.github.io/tf-analyze"
  },
  "keywords": "robustness, high, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# ⚠️ ROB-FOREACH-002 — for_each keyset is derived from another resource's attributes (apply-flicker)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-FOREACH-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-FOREACH-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-FOREACH-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **for_each keyset is derived from another resource's attributes (apply-flicker).** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`foreach_keyset_unstable`** — _a `foreach_keyset_unstable` pattern._
  A resource's `for_each` keyset is computed from another managed
resource's attribute. Every plan that mutates the upstream
resource set (add, remove, replace) re-keys this resource and
forces destroy/create on every existing instance — classic
apply-flicker. The fix is usually to key on a stable input
variable instead of a runtime attribute.

## Why it likely fired

A resource's `for_each` keyset is computed from another managed
resource's attribute. Every plan that mutates the upstream
resource set (add, remove, replace) re-keys this resource and
forces destroy/create on every existing instance — classic
apply-flicker. The fix is usually to key on a stable input
variable instead of a runtime attribute.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-FOREACH-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace the runtime-attribute keyset with a stable input keyset.

```hcl
# ❌ Anti-pattern: keys depend on aws_subnet IDs that AWS allocates
resource "aws_route_table_association" "rta" {
  for_each       = toset(aws_subnet.private[*].id)
  subnet_id      = each.key
  route_table_id = aws_route_table.private.id
}

# ✅ Fix: key on the same input that drives subnet creation
resource "aws_route_table_association" "rta" {
  for_each       = toset(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private[each.key].id
  route_table_id = aws_route_table.private.id
}
```

When the keyset is genuinely runtime (e.g., looked up via a `data`
source you don't control), wrap the consumers in a `null_resource`
with `triggers` so churn is at least observable, and document the
trade-off near the `for_each` line.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "aws_route_table_association" "rta" {
  for_each       = toset(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private[each.key].id
  route_table_id = aws_route_table.private.id
}
```

_Migrating an existing for_each from runtime keys to input keys is a
destroy/create unless paired with `moved` blocks for every instance.
Plan carefully on stateful resources; for stateless associations
(route-table associations, IAM attachments), the churn is usually
acceptable._

## Verification

After the fix, run `terraform plan` against an unchanged config —
diff should be zero. Then add an item to the input variable and
re-plan: only the new instance should appear, not destroy/create
on every prior instance.

## References

**Related rules**
  - [`ROB-FOREACH-001`](./ROB-FOREACH-001.md)
  - [`ROB-COUNTREF-001`](./ROB-COUNTREF-001.md)
  - [`ROB-COUNTREF-002`](./ROB-COUNTREF-002.md)

**Source**
  - [`catalog/ROB-FOREACH-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-FOREACH-002.yaml) — canonical YAML

## Family

See also rules in the `ROB-FOREACH-*` family:

- [`ROB-FOREACH-001`](./ROB-FOREACH-001.md) — for_each over list instead of map/set

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-FOREACH-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-FOREACH-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-FOREACH-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
{% if site.giscus.enabled %}
---

## Discussion

<script src="https://giscus.app/client.js"
        data-repo="{{ site.giscus.repo }}"
        data-repo-id="{{ site.giscus.repo_id }}"
        data-category="{{ site.giscus.category }}"
        data-category-id="{{ site.giscus.category_id }}"
        data-mapping="{{ site.giscus.mapping }}"
        data-strict="0"
        data-reactions-enabled="{{ site.giscus.reactions }}"
        data-emit-metadata="{{ site.giscus.emit_metadata }}"
        data-input-position="{{ site.giscus.input_position }}"
        data-theme="{{ site.giscus.theme }}"
        data-lang="en"
        crossorigin="anonymous"
        async>
</script>

{% endif %}
