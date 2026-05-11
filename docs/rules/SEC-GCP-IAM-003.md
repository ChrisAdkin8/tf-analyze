---
title: "SEC-GCP-IAM-003 — Member has both project-level and resource-level IAM grants"
description: "tf-analyze rule SEC-GCP-IAM-003 (HIGH · security): Member has both project-level and resource-level IAM grants"
keywords: "security, high, terraform, iac, gcp, cis-1.6, mitre-T1098.001, mitre-T1078.004, cwe-269, d3-pa, nist-csf-pr.ac-4, nist-800-53-ac-6, csa-ccm-iam-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-IAM-003 \u2014 Member has both project-level and resource-level IAM grants",
  "description": "Remove the project-level binding. Keep the resource-level bindings \u2014\nthey encode the actual access boundary. If you genuinely need the\nmember to span multiple resources of the same type, prefer one\nresource-level binding per target rather t",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-IAM-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-IAM-003/"
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
  "keywords": "security, high, terraform, CIS 1.6, MITRE T1098.001, MITRE T1078.004, CWE-269, D3-PA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-GCP-IAM-003 — Member has both project-level and resource-level IAM grants

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-IAM-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-IAM-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-IAM-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Member has both project-level and resource-level IAM grants.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`graph_check`** — _a corpus-wide graph check fired (cross-resource invariant)._
  A member (service account, group, user) holds a `google_project_iam_*`
binding AND one or more resource-level bindings (bucket, topic, KMS
key, etc.). The project-level grant supersedes the resource-level
scoping, making the resource-level binding pointless and signalling
that the project-level role is broader than intended.

## Why it likely fired

A member (service account, group, user) holds a `google_project_iam_*`
binding AND one or more resource-level bindings (bucket, topic, KMS
key, etc.). The project-level grant supersedes the resource-level
scoping, making the resource-level binding pointless and signalling
that the project-level role is broader than intended.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-IAM-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove the project-level binding. Keep the resource-level bindings —
they encode the actual access boundary. If you genuinely need the
member to span multiple resources of the same type, prefer one
resource-level binding per target rather than collapsing to the
project level (which also covers resources you didn't intend).

If the project-level grant is unavoidable (e.g. a baseline role like
`roles/monitoring.viewer`), delete the redundant resource-level
binding and document why the broader scope is required.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Remove the project-level binding; keep only resource-level bindings
resource "google_storage_bucket_iam_member" "app" {
  bucket = google_storage_bucket.app.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.app.email}"
}
# Delete: google_project_iam_member for the same service account
```

## Verification

After applying, the member should appear in either project IAM or
resource IAM but not both. `gcloud projects get-iam-policy <project>`
+ `gcloud storage buckets get-iam-policy gs://<bucket>` (or the
equivalent for the resource type) should not show overlap.

## References

**CIS Benchmark**
  - `CIS 1.6`

**OWASP IaC Cheat Sheet**
  - [`Develop and Distribute / Resource Permission Minimization`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1098.001`](https://attack.mitre.org/techniques/T1098/001/)
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**CWE**
  - [`CWE-269`](https://cwe.mitre.org/data/definitions/269.html)

**MITRE D3FEND**
  - [`D3-PA`](https://d3fend.mitre.org/technique/D3-PA/)

**NIST CSF 2.0**
  - [`PR.AC-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-6`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-6)

**CSA CCM v4**
  - [`IAM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Related rules**
  - [`SEC-IAM-001`](./SEC-IAM-001.md)
  - [`SEC-IAM-002`](./SEC-IAM-002.md)

**Source**
  - [`catalog/SEC-GCP-IAM-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-IAM-003.yaml) — canonical YAML

## Family

See also rules in the `SEC-GCP-IAM-*` family:

- [`SEC-GCP-IAM-001`](./SEC-GCP-IAM-001.md) — Project-level binding of overly broad role
- [`SEC-GCP-IAM-002`](./SEC-GCP-IAM-002.md) — Public IAM binding (allUsers / allAuthenticatedUsers)

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-IAM-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-IAM-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-IAM-003
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
