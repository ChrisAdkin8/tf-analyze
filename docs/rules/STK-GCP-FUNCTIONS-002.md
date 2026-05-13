---
title: "STK-GCP-FUNCTIONS-002 — GCP Cloud Function uses default service account"
description: "tf-analyze rule STK-GCP-FUNCTIONS-002 (HIGH · stack): GCP Cloud Function uses default service account"
keywords: "stack, high, terraform, iac, gcp, cis-1.4, mitre-T1078.004, cwe-250, cwe-272, d3-lam, nist-csf-pr.ac-4, nist-800-53-ac-6, csa-ccm-iam-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-FUNCTIONS-002 \u2014 GCP Cloud Function uses default service account",
  "description": "Provision a dedicated service account with the minimum roles the\nfunction needs, and bind it to the function:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-FUNCTIONS-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-FUNCTIONS-002/"
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
  "keywords": "stack, high, terraform, CIS 1.4, MITRE T1078.004, CWE-250, CWE-272, D3-LAM",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-GCP-FUNCTIONS-002 — GCP Cloud Function uses default service account

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-FUNCTIONS-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-FUNCTIONS-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-FUNCTIONS-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Cloud Function uses default service account.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_cloudfunctions_function` (`service_account_email`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_cloudfunctions_function` has no `service_account_email`.
The function runs as the project's default App Engine service
account, which is granted broad `roles/editor` at project
creation. A code-execution flaw in the function inherits
project-wide write access. Equivalent to the SEC-GCP-COMPUTE-SA-001
finding for GCE.
2. **`resource_missing_arg`** on `google_cloudfunctions2_function` (`service_config.service_account_email`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_cloudfunctions2_function` has no
`service_config.service_account_email`. v2 function falls back to
the over-privileged Compute Engine default SA.

## Why it likely fired

`google_cloudfunctions_function` has no `service_account_email`.
The function runs as the project's default App Engine service
account, which is granted broad `roles/editor` at project
creation. A code-execution flaw in the function inherits
project-wide write access. Equivalent to the SEC-GCP-COMPUTE-SA-001
finding for GCE.

`google_cloudfunctions2_function` has no
`service_config.service_account_email`. v2 function falls back to
the over-privileged Compute Engine default SA.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-FUNCTIONS-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Provision a dedicated service account with the minimum roles the
function needs, and bind it to the function:

    resource "google_service_account" "fn" {
      account_id   = "fn-process-events"
      display_name = "process-events function"
    }

    resource "google_cloudfunctions2_function" "main" {
      # ...
      service_config {
        service_account_email = google_service_account.fn.email
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_service_account" "fn" {
  account_id   = "fn-process-events"
  display_name = "process-events function"
}

resource "google_cloudfunctions2_function" "example" {
  name     = "process-events"
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

  service_config {
    service_account_email = google_service_account.fn.email
  }
}
```

_Switching service accounts requires the new SA to have the same roles as the old default-SA permissions the function actually used; audit Cloud Audit Logs first to enumerate._

## Verification

```sh
`gcloud functions describe <name> --format='value(serviceConfig.serviceAccountEmail)'`
must NOT return `<project>@appspot.gserviceaccount.com` or
`<project-number>-compute@developer.gserviceaccount.com`.
```

## References

**CIS Benchmark**
  - `CIS 1.4`

**PCI-DSS**
  - `Req-7.1`

**SOC 2 Trust Services Criteria**
  - `CC6.3`

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**CWE**
  - [`CWE-250`](https://cwe.mitre.org/data/definitions/250.html)
  - [`CWE-272`](https://cwe.mitre.org/data/definitions/272.html)

**MITRE D3FEND**
  - [`D3-LAM`](https://d3fend.mitre.org/technique/D3-LAM/)

**NIST CSF 2.0**
  - [`PR.AC-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-6`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-6)

**CSA CCM v4**
  - [`IAM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/STK-GCP-FUNCTIONS-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-FUNCTIONS-002.yaml) — canonical YAML

## Family

See also rules in the `STK-GCP-FUNCTIONS-*` family:

- [`STK-GCP-FUNCTIONS-001`](./STK-GCP-FUNCTIONS-001.md) — GCP Cloud Function uses end-of-life runtime

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-FUNCTIONS-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-FUNCTIONS-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-FUNCTIONS-002
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
