---
title: "ROB-GCP-LIFECYCLE-001 — Stateful resource missing lifecycle.prevent_destroy"
description: "tf-analyze rule ROB-GCP-LIFECYCLE-001 (HIGH · robustness): Stateful resource missing lifecycle.prevent_destroy"
keywords: "robustness, high, terraform, iac, gcp, mitre-T1485, cwe-693, nist-csf-pr.ip-4, nist-800-53-cm-3, csa-ccm-bcr-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-GCP-LIFECYCLE-001 \u2014 Stateful resource missing lifecycle.prevent_destroy",
  "description": "Add `lifecycle { prevent_destroy = true }` to any resource that holds\nirrecoverable state. The block forces operators to remove the line\nintentionally before a destroy plan can succeed \u2014 a deliberate friction\nthat has saved real outages.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-GCP-LIFECYCLE-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-GCP-LIFECYCLE-001/"
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
  "keywords": "robustness, high, terraform, MITRE T1485, CWE-693",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# ⚠️ ROB-GCP-LIFECYCLE-001 — Stateful resource missing lifecycle.prevent_destroy

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-GCP-LIFECYCLE-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-GCP-LIFECYCLE-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-GCP-LIFECYCLE-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Stateful resource missing lifecycle.prevent_destroy.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_storage_bucket` (`lifecycle.prevent_destroy`) — _the resource is missing a required attribute (or nested attribute path)._
2. **`resource_missing_arg`** on `google_spanner_instance` (`lifecycle.prevent_destroy`) — _the resource is missing a required attribute (or nested attribute path)._
3. **`resource_missing_arg`** on `google_spanner_database` (`lifecycle.prevent_destroy`) — _the resource is missing a required attribute (or nested attribute path)._
4. **`resource_missing_arg`** on `google_sql_database_instance` (`lifecycle.prevent_destroy`) — _the resource is missing a required attribute (or nested attribute path)._
5. **`resource_missing_arg`** on `google_compute_disk` (`lifecycle.prevent_destroy`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-GCP-LIFECYCLE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `lifecycle { prevent_destroy = true }` to any resource that holds
irrecoverable state. The block forces operators to remove the line
intentionally before a destroy plan can succeed — a deliberate friction
that has saved real outages.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_sql_database_instance" "example" {
  # ... other arguments ...
  lifecycle {
    prevent_destroy = true
  }
}
```

## Verification

Run `terraform plan -destroy` and confirm Terraform refuses to destroy
the resource with an error citing the prevent_destroy lifecycle rule.

## References

**SOC 2 Trust Services Criteria**
  - `A1.2`

**OWASP IaC Cheat Sheet**
  - [`Deploy / Resource Decommissioning Process`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1485`](https://attack.mitre.org/techniques/T1485/)

**CWE**
  - [`CWE-693`](https://cwe.mitre.org/data/definitions/693.html)

**NIST CSF 2.0**
  - [`PR.IP-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CM-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cm-3)

**CSA CCM v4**
  - [`BCR-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/ROB-GCP-LIFECYCLE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-GCP-LIFECYCLE-001.yaml) — canonical YAML

## Family

See also rules in the `ROB-GCP-LIFECYCLE-*` family:

- [`ROB-GCP-LIFECYCLE-002`](./ROB-GCP-LIFECYCLE-002.md) — Stateful resource has force_destroy=true

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-GCP-LIFECYCLE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-GCP-LIFECYCLE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-GCP-LIFECYCLE-001
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
