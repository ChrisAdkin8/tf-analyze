---
title: "SEC-K8S-SA-001 — kubernetes_service_account allows automount of API token"
description: "tf-analyze rule SEC-K8S-SA-001 (MEDIUM · security): kubernetes_service_account allows automount of API token"
keywords: "security, medium, terraform, iac, cis-5.1.5, cis-5.1.6, mitre-T1528, mitre-T1078.001, cwe-269, cwe-732, nist-csf-pr.ac-4, nist-800-53-ac-6, nist-800-53-ia-5, csa-ccm-iam-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-K8S-SA-001 \u2014 kubernetes_service_account allows automount of API token",
  "description": "Set `automount_service_account_token = false` at the SA level\n(deny-by-default), then opt in selectively at the Pod spec with\n`automountServiceAccountToken: true` only on the workloads that\nactually call the API.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-SA-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-SA-001/"
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
  "keywords": "security, medium, terraform, CIS 5.1.5, CIS 5.1.6, MITRE T1528, MITRE T1078.001, CWE-269, CWE-732",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-K8S-SA-001 — kubernetes_service_account allows automount of API token

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-K8S-SA-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-K8S-SA-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-K8S-SA-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **kubernetes_service_account allows automount of API token.** This rule has `default_urgency: MEDIUM` and operates on a environment blast radius. 

## What this checks

1. **`resource_body_contains`** on `kubernetes_service_account` matching `/(?m)^\s*automount_service_account_token\s*=\s*true\b/` — _the resource body matches a regex inside the block._
  `kubernetes_service_account` explicitly sets
`automount_service_account_token = true`, projecting the SA's
bearer token into every pod that mounts it. Compromise of any
such pod (RCE, container breakout, log access) yields the
token; the token is reusable cluster-wide until rotated.
2. **`resource_missing_arg`** on `kubernetes_service_account` (`automount_service_account_token`) — _the resource is missing a required attribute (or nested attribute path)._
  `kubernetes_service_account` omits `automount_service_account_token`
entirely. The Kubernetes default is `true`, so the omission is
functionally equivalent to opting into automount — the SA
token is projected into every pod that runs under this SA.
3. **`resource_body_contains`** on `kubernetes_service_account_v1` matching `/(?m)^\s*automount_service_account_token\s*=\s*true\b/` — _the resource body matches a regex inside the block._
  `kubernetes_service_account_v1` — same anti-pattern in the
API-versioned alias.

## Why it likely fired

`kubernetes_service_account` explicitly sets
`automount_service_account_token = true`, projecting the SA's
bearer token into every pod that mounts it. Compromise of any
such pod (RCE, container breakout, log access) yields the
token; the token is reusable cluster-wide until rotated.

`kubernetes_service_account` omits `automount_service_account_token`
entirely. The Kubernetes default is `true`, so the omission is
functionally equivalent to opting into automount — the SA
token is projected into every pod that runs under this SA.

`kubernetes_service_account_v1` — same anti-pattern in the
API-versioned alias.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-SA-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `automount_service_account_token = false` at the SA level
(deny-by-default), then opt in selectively at the Pod spec with
`automountServiceAccountToken: true` only on the workloads that
actually call the API.

    resource "kubernetes_service_account" "app" {
      metadata {
        name      = "app"
        namespace = "app"
      }
      automount_service_account_token = false
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "kubernetes_service_account" "app" {
  metadata {
    name      = "app"
    namespace = "app"
  }
  automount_service_account_token = false
}
```

_Setting automount to false drops the projected token on every pod that runs under this SA. Workloads that genuinely call the API will start failing auth until they opt back in at the Pod spec._

## Verification

```sh
`kubectl get sa -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.automountServiceAccountToken}{"\n"}{end}'`
should show `false` for every SA except those whose pods genuinely
need API access.
```

## References

**CIS Benchmark**
  - `CIS 5.1.5`
  - `CIS 5.1.6`

**PCI-DSS**
  - `Req-7.2.2`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1528`](https://attack.mitre.org/techniques/T1528/)
  - [`T1078.001`](https://attack.mitre.org/techniques/T1078/001/)

**CWE**
  - [`CWE-269`](https://cwe.mitre.org/data/definitions/269.html)
  - [`CWE-732`](https://cwe.mitre.org/data/definitions/732.html)

**NIST CSF 2.0**
  - [`PR.AC-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-6`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-6)
  - [`IA-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ia-5)

**CSA CCM v4**
  - [`IAM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**OWASP (namespaced)**
  - `K03`

**Source**
  - [`catalog/SEC-K8S-SA-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-SA-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-SA-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-SA-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-SA-001
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
