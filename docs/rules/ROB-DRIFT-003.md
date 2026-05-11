---
title: "ROB-DRIFT-003 — ignore_changes lists too many attributes (drift-disable by attrition)"
description: "tf-analyze rule ROB-DRIFT-003 (LOW · robustness): ignore_changes lists too many attributes (drift-disable by attrition)"
keywords: "robustness, low, terraform, iac, mitre-T1562.001, cwe-693, nist-csf-pr.ip-3, nist-800-53-cm-3, csa-ccm-ccc-05"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-DRIFT-003 \u2014 ignore_changes lists too many attributes (drift-disable by attrition)",
  "description": "Audit the `ignore_changes` list. For each attribute:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-DRIFT-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-DRIFT-003/"
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
  "keywords": "robustness, low, terraform, MITRE T1562.001, CWE-693",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# ℹ️ ROB-DRIFT-003 — ignore_changes lists too many attributes (drift-disable by attrition)

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-DRIFT-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-DRIFT-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-DRIFT-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **ignore_changes lists too many attributes (drift-disable by attrition).** This rule has `default_urgency: LOW` and operates on a single resource blast radius. 

## What this checks

1. **`ignore_changes_overuse`** — _a `ignore_changes_overuse` pattern._
  `lifecycle.ignore_changes` enumerates more than 5 specific
attributes. Listing many attributes is "drift disable by
attrition" — the team ratcheted up the list one attribute at a
time, and the practical effect is the same as `ignore_changes
= all` with extra steps. ROB-DRIFT-001 catches the explicit
`all` form; ROB-DRIFT-002 catches the wildcard `["*"]` and
`[tags]` shapes; this rule is the third leg of the same
regression: drift detection has been disabled in fact, just
not in name.

Default urgency is LOW because legitimate uses exist
(autoscaling group `desired_capacity`, Lambda code packages,
ECS task definitions in CD pipelines) — the value is in the
*signal*, not the gate.

## Why it likely fired

`lifecycle.ignore_changes` enumerates more than 5 specific
attributes. Listing many attributes is "drift disable by
attrition" — the team ratcheted up the list one attribute at a
time, and the practical effect is the same as `ignore_changes
= all` with extra steps. ROB-DRIFT-001 catches the explicit
`all` form; ROB-DRIFT-002 catches the wildcard `["*"]` and
`[tags]` shapes; this rule is the third leg of the same
regression: drift detection has been disabled in fact, just
not in name.

Default urgency is LOW because legitimate uses exist
(autoscaling group `desired_capacity`, Lambda code packages,
ECS task definitions in CD pipelines) — the value is in the
*signal*, not the gate.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-DRIFT-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Audit the `ignore_changes` list. For each attribute:

  - If the attribute is genuinely managed out-of-band (autoscaling,
    pipelines, CRDs), keep it and add a comment explaining why.
  - If it's there because a noisy pipeline is rewriting it, fix
    the pipeline rather than ignoring the attribute.
  - If it's there because a migration removed an old field, delete
    the entry — Terraform won't complain about an unknown ignore.

When more than ~5 attributes are genuinely managed out-of-band the
resource may be the wrong one to import into Terraform at all —
consider a `data` source or a provider-managed resource that
returns the desired_state directly.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_autoscaling_group" "app" {
  # ... configuration ...
  lifecycle {
    # Pipeline-managed; intentionally excluded from drift detection.
    ignore_changes = [
      desired_capacity,  # set by app autoscaler
      target_group_arns, # rotated by blue/green deploys
    ]
  }
}
```

## Verification

Re-run `terraform plan` after pruning the list. The diff should
show only attributes that are genuinely intended to converge.

## References

**OWASP IaC Cheat Sheet**
  - [`Runtime / Immutable Infrastructure Model`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1562.001`](https://attack.mitre.org/techniques/T1562/001/)

**CWE**
  - [`CWE-693`](https://cwe.mitre.org/data/definitions/693.html)

**NIST CSF 2.0**
  - [`PR.IP-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CM-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cm-3)

**CSA CCM v4**
  - [`CCC-05`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Related rules**
  - [`ROB-DRIFT-001`](./ROB-DRIFT-001.md)
  - [`ROB-DRIFT-002`](./ROB-DRIFT-002.md)

**Source**
  - [`catalog/ROB-DRIFT-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-DRIFT-003.yaml) — canonical YAML

## Family

See also rules in the `ROB-DRIFT-*` family:

- [`ROB-DRIFT-001`](./ROB-DRIFT-001.md) — Resource uses ignore_changes = all
- [`ROB-DRIFT-002`](./ROB-DRIFT-002.md) — ignore_changes hides too much (wildcard, or tags-wide on a tagged resource)

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-DRIFT-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-DRIFT-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-DRIFT-003
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
