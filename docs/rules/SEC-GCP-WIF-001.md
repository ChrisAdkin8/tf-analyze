---
title: "SEC-GCP-WIF-001 — GCP Workload Identity Federation pool provider missing attribute_condition"
description: "tf-analyze rule SEC-GCP-WIF-001 (CRITICAL · security): GCP Workload Identity Federation pool provider missing attribute_condition"
keywords: "security, critical, terraform, iac, gcp, cis-1.13, mitre-T1078.004, mitre-T1199, cwe-284, cwe-287, d3-uac, nist-csf-pr.ac-1, nist-csf-pr.ac-4, nist-800-53-ac-2, nist-800-53-ac-3, nist-800-53-ia-5, csa-ccm-iam-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-WIF-001 \u2014 GCP Workload Identity Federation pool provider missing attribute_condition",
  "description": "Add a CEL `attribute_condition` that pins the exact external\nidentity. For GitHub Actions:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-WIF-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-WIF-001/"
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
  "keywords": "security, critical, terraform, CIS 1.13, MITRE T1078.004, MITRE T1199, CWE-284, CWE-287, D3-UAC",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-GCP-WIF-001 — GCP Workload Identity Federation pool provider missing attribute_condition

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-WIF-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-WIF-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-WIF-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Workload Identity Federation pool provider missing attribute_condition.** This rule has `default_urgency: CRITICAL` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_iam_workload_identity_pool_provider` (`attribute_condition`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_iam_workload_identity_pool_provider` has no
`attribute_condition`. Without a CEL expression restricting which
external identities can mint Google tokens, ANY workload that
authenticates against the upstream OIDC issuer (any GitHub repo,
any GitLab project, any AWS account) can impersonate this
service account. This is the GCP equivalent of an IAM role with
`Principal: "*"` in its trust policy.

## Why it likely fired

`google_iam_workload_identity_pool_provider` has no
`attribute_condition`. Without a CEL expression restricting which
external identities can mint Google tokens, ANY workload that
authenticates against the upstream OIDC issuer (any GitHub repo,
any GitLab project, any AWS account) can impersonate this
service account. This is the GCP equivalent of an IAM role with
`Principal: "*"` in its trust policy.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-WIF-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a CEL `attribute_condition` that pins the exact external
identity. For GitHub Actions:

    resource "google_iam_workload_identity_pool_provider" "github" {
      # ...
      attribute_condition = "assertion.repository == 'my-org/my-repo'"
    }

For AWS:

    attribute_condition = "google.subject.startsWith('arn:aws:iam::123456789012:role/')"

Pair with `attribute_mapping` so the assertion claims you constrain
are actually surfaced as `google.subject`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.gh.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-actions"
  display_name                       = "GitHub Actions"

  attribute_mapping = {
    "google.subject"        = "assertion.sub"
    "attribute.repository"  = "assertion.repository"
  }

  attribute_condition = "assertion.repository == 'my-org/my-repo'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
```

_Tightening the condition does not affect workloads that already match the constraint._

## Verification

```sh
`gcloud iam workload-identity-pools providers describe <provider-id> \
  --workload-identity-pool=<pool-id> --location=global` must return a
non-empty `attributeCondition` field.
```

## References

**CIS Benchmark**
  - `CIS 1.13`

**PCI-DSS**
  - `Req-7.1`

**SOC 2 Trust Services Criteria**
  - `CC6.3`

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)
  - [`T1199`](https://attack.mitre.org/techniques/T1199/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)
  - [`CWE-287`](https://cwe.mitre.org/data/definitions/287.html)

**MITRE D3FEND**
  - [`D3-UAC`](https://d3fend.mitre.org/technique/D3-UAC/)

**NIST CSF 2.0**
  - [`PR.AC-1`](https://www.nist.gov/cyberframework)
  - [`PR.AC-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-2`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-2)
  - [`AC-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-3)
  - [`IA-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ia-5)

**CSA CCM v4**
  - [`IAM-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-WIF-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-WIF-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-WIF-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-WIF-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-WIF-001
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
