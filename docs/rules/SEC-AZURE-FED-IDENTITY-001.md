---
title: "SEC-AZURE-FED-IDENTITY-001 — Azure federated identity credential accepts wildcard subject claim"
description: "tf-analyze rule SEC-AZURE-FED-IDENTITY-001 (CRITICAL · security): Azure federated identity credential accepts wildcard subject claim"
keywords: "security, critical, terraform, iac, azure, cis-1.21, mitre-T1078.004, mitre-T1199, cwe-284, cwe-287, d3-uac, nist-csf-pr.ac-1, nist-csf-pr.ac-4, nist-800-53-ac-2, nist-800-53-ac-3, nist-800-53-ia-5, csa-ccm-iam-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-FED-IDENTITY-001 \u2014 Azure federated identity credential accepts wildcard subject claim",
  "description": "Replace the wildcard with the exact OIDC subject claim of the workload\nthat should assume this UAMI. For GitHub Actions:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-FED-IDENTITY-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-FED-IDENTITY-001/"
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
  "keywords": "security, critical, terraform, CIS 1.21, MITRE T1078.004, MITRE T1199, CWE-284, CWE-287, D3-UAC",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-AZURE-FED-IDENTITY-001 — Azure federated identity credential accepts wildcard subject claim

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-FED-IDENTITY-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-FED-IDENTITY-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-FED-IDENTITY-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure federated identity credential accepts wildcard subject claim.** This rule has `default_urgency: CRITICAL` and operates on a environment blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_federated_identity_credential` (`subject`) matching `/^.*\*/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Federated identity credential `subject` matches a wildcard. A
wildcard subject means ANY GitHub repo, ANY GitLab project, or ANY
workload that authenticates against the configured issuer can
assume this managed identity. This is functionally equivalent to a
public-principal IAM role.

## Why it likely fired

Federated identity credential `subject` matches a wildcard. A
wildcard subject means ANY GitHub repo, ANY GitLab project, or ANY
workload that authenticates against the configured issuer can
assume this managed identity. This is functionally equivalent to a
public-principal IAM role.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-FED-IDENTITY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace the wildcard with the exact OIDC subject claim of the workload
that should assume this UAMI. For GitHub Actions:

    subject = "repo:my-org/my-repo:ref:refs/heads/main"

For GitLab CI:

    subject = "project_path:my-group/my-project:ref_type:branch:ref:main"

For Kubernetes service accounts (AKS workload identity):

    subject = "system:serviceaccount:my-namespace:my-sa"

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_federated_identity_credential" "github" {
  name                = "github-main"
  resource_group_name = azurerm_resource_group.main.name
  parent_id           = azurerm_user_assigned_identity.gh.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = "repo:my-org/my-repo:ref:refs/heads/main"
}
```

_Tightening the subject does not affect callers that already match the exact claim._

## Verification

```sh
`az identity federated-credential list --identity-name <name> \
  --resource-group <rg> --query "[].subject"` must return no entries
containing `*` (other than escaped literal asterisks).
```

## References

**CIS Benchmark**
  - `CIS 1.21`

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
  - [`catalog/SEC-AZURE-FED-IDENTITY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-FED-IDENTITY-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-FED-IDENTITY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-FED-IDENTITY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-FED-IDENTITY-001
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
