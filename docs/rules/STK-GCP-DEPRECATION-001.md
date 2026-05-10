---
title: "STK-GCP-DEPRECATION-001 — Resource uses deprecated argument"
description: "tf-analyze rule STK-GCP-DEPRECATION-001 (MEDIUM · robustness): Resource uses deprecated argument"
keywords: "robustness, medium, terraform, iac, gcp, mitre-T1195.002, cwe-1104, d3-sca"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-DEPRECATION-001 \u2014 Resource uses deprecated argument",
  "description": "Replace deprecated arguments with their successors before the next major\nprovider version removes them. Check the Google provider changelog for\nmigration guidance.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-DEPRECATION-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-DEPRECATION-001/"
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
  "keywords": "robustness, medium, terraform, MITRE T1195.002, CWE-1104, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-GCP-DEPRECATION-001 — Resource uses deprecated argument

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-DEPRECATION-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-DEPRECATION-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-DEPRECATION-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Resource uses deprecated argument.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `google_container_cluster` (`enable_legacy_abac`) matching `/.*/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  enable_legacy_abac is deprecated; remove it (ABAC disabled by default)
2. **`resource_arg`** on `google_container_cluster` (`logging_service`) matching `/.*/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  logging_service is deprecated; use logging_config block instead
3. **`resource_arg`** on `google_container_cluster` (`monitoring_service`) matching `/.*/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  monitoring_service is deprecated; use monitoring_config block instead
4. **`resource_arg`** on `google_compute_instance` (`metadata_startup_script`) matching `/.*/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  metadata_startup_script is deprecated; use metadata.startup-script instead
5. **`grep`** matching `/resource\s+"google_compute_address".*\n.*\baddress\b/` — _a textual regex matched somewhere in the file._
  google_compute_address.address argument renamed in v6

## Why it likely fired

enable_legacy_abac is deprecated; remove it (ABAC disabled by default)

logging_service is deprecated; use logging_config block instead

monitoring_service is deprecated; use monitoring_config block instead

metadata_startup_script is deprecated; use metadata.startup-script instead

google_compute_address.address argument renamed in v6

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-DEPRECATION-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace deprecated arguments with their successors before the next major
provider version removes them. Check the Google provider changelog for
migration guidance.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_container_cluster" "app" {
  # Remove deprecated enable_legacy_abac — ABAC is disabled by default
  # Remove deprecated logging_service / monitoring_service — use blocks instead
  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }
  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
  }
}

resource "google_compute_instance" "app" {
  metadata = {
    "startup-script" = file("${path.module}/startup.sh")
  }
  # Remove deprecated metadata_startup_script argument
}
```

## Verification

Run `terraform validate` and `terraform plan` — no deprecation warnings
should appear.

## References

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1104`](https://cwe.mitre.org/data/definitions/1104.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**Source**
  - [`catalog/STK-GCP-DEPRECATION-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-DEPRECATION-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-DEPRECATION-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-DEPRECATION-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-DEPRECATION-001
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
