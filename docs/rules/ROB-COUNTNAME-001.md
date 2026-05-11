---
title: "ROB-COUNTNAME-001 — Resource external name embeds count.index — renumber-risk on apply"
description: "tf-analyze rule ROB-COUNTNAME-001 (HIGH · robustness): Resource external name embeds count.index — renumber-risk on apply"
keywords: "robustness, high, terraform, iac, mitre-T1485, cwe-1188, d3-cspp, nist-csf-pr.ip-3, nist-800-53-cm-6, nist-800-53-si-7, csa-ccm-ccc-04, slsa-source"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-COUNTNAME-001 \u2014 Resource external name embeds count.index \u2014 renumber-risk on apply",
  "description": "Migrate to ``for_each`` with a stable map/set key derived from\nbusiness identity rather than positional index:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-COUNTNAME-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-COUNTNAME-001/"
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
  "keywords": "robustness, high, terraform, MITRE T1485, CWE-1188, D3-CSPP",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# ⚠️ ROB-COUNTNAME-001 — Resource external name embeds count.index — renumber-risk on apply

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-COUNTNAME-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-COUNTNAME-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-COUNTNAME-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Resource external name embeds count.index — renumber-risk on apply.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`count_index_in_name`** — _a `count_index_in_name` pattern._
  Resource declares ``count = N`` AND has a name-like attribute
(``name``, ``bucket``, ``identifier``, ``hostname``,
``db_name``, ``instance_name``, ``cluster_identifier``,
``function_name``, ``topic_name``, ``queue_name``,
``table_name``, ``role_name``, ``user_name``,
``repository_name``, ``key_name``) whose value interpolates
``${count.index}`` or ``count.index``. Changing ``count``
from N to M (with M < N) destroys instance ``[M..N-1]``;
reordering destroys-and-recreates every instance whose
index shifts. The external name encodes that index, so
Terraform can't even rebuild the same resource on a different
slot — the apply *will* destroy real infrastructure.

## Why it likely fired

Resource declares ``count = N`` AND has a name-like attribute
(``name``, ``bucket``, ``identifier``, ``hostname``,
``db_name``, ``instance_name``, ``cluster_identifier``,
``function_name``, ``topic_name``, ``queue_name``,
``table_name``, ``role_name``, ``user_name``,
``repository_name``, ``key_name``) whose value interpolates
``${count.index}`` or ``count.index``. Changing ``count``
from N to M (with M < N) destroys instance ``[M..N-1]``;
reordering destroys-and-recreates every instance whose
index shifts. The external name encodes that index, so
Terraform can't even rebuild the same resource on a different
slot — the apply *will* destroy real infrastructure.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-COUNTNAME-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Migrate to ``for_each`` with a stable map/set key derived from
business identity rather than positional index:

    # Before — renumber-fragile:
    resource "aws_instance" "web" {
      count         = 3
      ami           = data.aws_ami.al2.id
      instance_type = "t3.micro"
      tags          = { Name = "web-${count.index}" }
    }

    # After — stable identity:
    resource "aws_instance" "web" {
      for_each      = toset(["alpha", "beta", "gamma"])
      ami           = data.aws_ami.al2.id
      instance_type = "t3.micro"
      tags          = { Name = "web-${each.key}" }
    }

After ``for_each``, removing ``"beta"`` only destroys
``aws_instance.web["beta"]``. The other two instances retain
their state addresses *and* their external names. With the
count form, removing one in the middle destroys-and-recreates
every instance with a higher index.

If the resource is already deployed and you can't migrate
without a destroy, add ``lifecycle.prevent_destroy = true`` as
a tripwire and use ``terraform state mv`` for any index
reordering. Both are operational toil — for_each is the
durable fix.

## Verification

Run ``terraform plan`` after a one-line count decrement (e.g.
``count = N`` → ``count = N - 1``). If the plan says ``destroy``
for instances beyond the new count *and* the external name
embedded ``count.index``, the rule fires correctly.

Confirm the migration target by running plan against the
``for_each`` form with the same set membership — Terraform should
produce zero changes.

## References

**MITRE ATT&CK**
  - [`T1485`](https://attack.mitre.org/techniques/T1485/)

**CWE**
  - [`CWE-1188`](https://cwe.mitre.org/data/definitions/1188.html)

**MITRE D3FEND**
  - [`D3-CSPP`](https://d3fend.mitre.org/technique/D3-CSPP/)

**NIST CSF 2.0**
  - [`PR.IP-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CM-6`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cm-6)
  - [`SI-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=si-7)

**CSA CCM v4**
  - [`CCC-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**SLSA v1.0**
  - [`SLSA source`](https://slsa.dev/spec/v1.0/source-track)

**Related rules**
  - [`ROB-COUNT-001`](./ROB-COUNT-001.md)
  - [`ROB-COUNT-002`](./ROB-COUNT-002.md)
  - [`ROB-COUNTREF-001`](./ROB-COUNTREF-001.md)
  - [`ROB-FOREACH-001`](./ROB-FOREACH-001.md)
  - [`ROB-FOREACH-002`](./ROB-FOREACH-002.md)

**Source**
  - [`catalog/ROB-COUNTNAME-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-COUNTNAME-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-COUNTNAME-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-COUNTNAME-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-COUNTNAME-001
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
