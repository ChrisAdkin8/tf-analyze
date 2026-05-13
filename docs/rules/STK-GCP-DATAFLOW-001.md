---
title: "STK-GCP-DATAFLOW-001 — GCP Dataflow job exposes workers to public IPs"
description: "tf-analyze rule STK-GCP-DATAFLOW-001 (MEDIUM · stack): GCP Dataflow job exposes workers to public IPs"
keywords: "stack, medium, terraform, iac, gcp, cis-3.5, mitre-T1190, cwe-284, nist-csf-pr.ac-5, nist-800-53-sc-7"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-DATAFLOW-001 \u2014 GCP Dataflow job exposes workers to public IPs",
  "description": "Force workers to private IP only:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-DATAFLOW-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-DATAFLOW-001/"
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
  "keywords": "stack, medium, terraform, CIS 3.5, MITRE T1190, CWE-284",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-GCP-DATAFLOW-001 — GCP Dataflow job exposes workers to public IPs

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-DATAFLOW-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-DATAFLOW-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-DATAFLOW-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Dataflow job exposes workers to public IPs.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_dataflow_job` (`ip_configuration`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_dataflow_job` has no `ip_configuration` set to
`WORKER_IP_PRIVATE`. Workers receive public IPs by default,
widening the attack surface and increasing egress cost.
2. **`resource_arg`** on `google_dataflow_job` (`ip_configuration`) matching `/^WORKER_IP_PUBLIC$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Dataflow job explicitly uses WORKER_IP_PUBLIC

## Why it likely fired

`google_dataflow_job` has no `ip_configuration` set to
`WORKER_IP_PRIVATE`. Workers receive public IPs by default,
widening the attack surface and increasing egress cost.

Dataflow job explicitly uses WORKER_IP_PUBLIC

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-DATAFLOW-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Force workers to private IP only:

    resource "google_dataflow_job" "main" {
      # ...
      ip_configuration = "WORKER_IP_PRIVATE"
      subnetwork       = google_compute_subnetwork.df.id
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_dataflow_job" "example" {
  name              = "etl"
  template_gcs_path = "gs://dataflow-templates/latest/Word_Count"
  temp_gcs_location = "gs://example/temp"
  ip_configuration  = "WORKER_IP_PRIVATE"
  subnetwork        = google_compute_subnetwork.df.id
}
```

## Verification

```sh
`gcloud dataflow jobs describe <id> --format='value(environment.ipConfiguration)'`
must return `WORKER_IP_PRIVATE`.
```

## References

**CIS Benchmark**
  - `CIS 3.5`

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**NIST CSF 2.0**
  - [`PR.AC-5`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-7)

**Source**
  - [`catalog/STK-GCP-DATAFLOW-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-DATAFLOW-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-DATAFLOW-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-DATAFLOW-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-DATAFLOW-001
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
