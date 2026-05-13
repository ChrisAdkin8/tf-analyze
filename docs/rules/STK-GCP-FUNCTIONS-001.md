---
title: "STK-GCP-FUNCTIONS-001 — GCP Cloud Function uses end-of-life runtime"
description: "tf-analyze rule STK-GCP-FUNCTIONS-001 (HIGH · stack): GCP Cloud Function uses end-of-life runtime"
keywords: "stack, high, terraform, iac, gcp, mitre-T1190, mitre-T1195.002, cwe-1104, d3-sca, nist-csf-id.sc-2, nist-800-53-sr-4, csa-ccm-ais-07, slsa-deps"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-FUNCTIONS-001 \u2014 GCP Cloud Function uses end-of-life runtime",
  "description": "Upgrade to a currently supported runtime. Google Cloud Functions\nsupported runtimes (May 2026):\n- Python: 3.10, 3.11, 3.12, 3.13\n- Node.js: 18, 20, 22\n- Go: 1.21, 1.22, 1.23\n- Java: 17, 21\n- .NET: 6, 8\n- Ruby: 3.2, 3.3",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-FUNCTIONS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-FUNCTIONS-001/"
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
  "keywords": "stack, high, terraform, MITRE T1190, MITRE T1195.002, CWE-1104, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-GCP-FUNCTIONS-001 — GCP Cloud Function uses end-of-life runtime

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-FUNCTIONS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-FUNCTIONS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-FUNCTIONS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Cloud Function uses end-of-life runtime.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `google_cloudfunctions_function` (`runtime`) matching `/^(python37|python38|nodejs10|nodejs12|nodejs14|nodejs16|go111|go113|go116|java11|dotnet3|ruby25|ruby27)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Cloud Functions v1 runtime out of support
2. **`resource_arg`** on `google_cloudfunctions2_function` (`build_config.runtime`) matching `/^(python37|python38|nodejs14|nodejs16|go116|go118|java11|dotnet3|ruby27)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Cloud Functions v2 runtime out of support
3. **`resource_body_contains`** on `google_cloudfunctions2_function` matching `/runtime\s*=\s*"(python37|python38|nodejs14|nodejs16|go116|go118|java11|dotnet3|ruby27)"/` — _the resource body matches a regex inside the block._
  Cloud Functions v2 runtime out of support (body match)

## Why it likely fired

Cloud Functions v1 runtime out of support

Cloud Functions v2 runtime out of support

Cloud Functions v2 runtime out of support (body match)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-FUNCTIONS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Upgrade to a currently supported runtime. Google Cloud Functions
supported runtimes (May 2026):
- Python: 3.10, 3.11, 3.12, 3.13
- Node.js: 18, 20, 22
- Go: 1.21, 1.22, 1.23
- Java: 17, 21
- .NET: 6, 8
- Ruby: 3.2, 3.3

Deprecated runtimes can no longer be deployed; existing deployments
continue to run but receive no security patches.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_cloudfunctions2_function" "example" {
  name     = "example"
  location = "us-central1"

  build_config {
    runtime     = "python312"
    entry_point = "main"
    source {
      storage_source {
        bucket = google_storage_bucket.source.name
        object = "source.zip"
      }
    }
  }
}
```

_Runtime upgrades may break source compatibility (removed stdlib APIs, dependency conflicts); test in a staging project first._

## Verification

```sh
`gcloud functions describe <name> --gen2 --format='value(buildConfig.runtime)'`
must return a supported runtime identifier (see GCP docs).
```

## References

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1104`](https://cwe.mitre.org/data/definitions/1104.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**NIST CSF 2.0**
  - [`ID.SC-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SR-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-4)

**CSA CCM v4**
  - [`AIS-07`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**SLSA v1.0**
  - [`SLSA deps`](https://slsa.dev/spec/v1.0/deps-track)

**Source**
  - [`catalog/STK-GCP-FUNCTIONS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-FUNCTIONS-001.yaml) — canonical YAML

## Family

See also rules in the `STK-GCP-FUNCTIONS-*` family:

- [`STK-GCP-FUNCTIONS-002`](./STK-GCP-FUNCTIONS-002.md) — GCP Cloud Function uses default service account

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-FUNCTIONS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-FUNCTIONS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-FUNCTIONS-001
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
