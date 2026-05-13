---
title: "STK-GCP-COMPOSER-001 — GCP Composer (Airflow) environment not private"
description: "tf-analyze rule STK-GCP-COMPOSER-001 (HIGH · stack): GCP Composer (Airflow) environment not private"
keywords: "stack, high, terraform, iac, gcp, cis-3.5, mitre-T1190, cwe-284, d3-nta, nist-csf-pr.ac-5, nist-800-53-sc-7"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-COMPOSER-001 \u2014 GCP Composer (Airflow) environment not private",
  "description": "Enable private environment so the underlying GKE and Cloud SQL\ncomponents have private IPs only:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-COMPOSER-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-COMPOSER-001/"
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
  "keywords": "stack, high, terraform, CIS 3.5, MITRE T1190, CWE-284, D3-NTA",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-GCP-COMPOSER-001 — GCP Composer (Airflow) environment not private

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-COMPOSER-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-COMPOSER-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-COMPOSER-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Composer (Airflow) environment not private.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_composer_environment` (`config.private_environment_config`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_composer_environment` has no `private_environment_config`.
The GKE cluster underneath has public IPs and the Airflow web UI
is reachable from the public internet (subject to IAM, but the
attack surface is still public).

## Why it likely fired

`google_composer_environment` has no `private_environment_config`.
The GKE cluster underneath has public IPs and the Airflow web UI
is reachable from the public internet (subject to IAM, but the
attack surface is still public).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-COMPOSER-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable private environment so the underlying GKE and Cloud SQL
components have private IPs only:

    resource "google_composer_environment" "main" {
      # ...
      config {
        private_environment_config {
          enable_private_endpoint = true
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_composer_environment" "example" {
  name   = "example"
  region = "us-central1"
  config {
    private_environment_config {
      enable_private_endpoint = true
    }
  }
}
```

## Verification

```sh
`gcloud composer environments describe <name> --location <l> \
  --format='value(config.privateEnvironmentConfig.enablePrivateEndpoint)'`
must return `True`.
```

## References

**CIS Benchmark**
  - `CIS 3.5`

**PCI-DSS**
  - `Req-1.3`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**MITRE D3FEND**
  - [`D3-NTA`](https://d3fend.mitre.org/technique/D3-NTA/)

**NIST CSF 2.0**
  - [`PR.AC-5`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-7)

**Source**
  - [`catalog/STK-GCP-COMPOSER-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-COMPOSER-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-COMPOSER-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-COMPOSER-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-COMPOSER-001
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
