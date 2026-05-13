---
title: "SEC-K8S-HELM-003 — helm_release weak supply-chain controls (`verify = false` OR `version` unpinned)"
description: "tf-analyze rule SEC-K8S-HELM-003 (HIGH · security): helm_release weak supply-chain controls (`verify = false` OR `version` unpinned)"
keywords: "security, high, terraform, iac, cis-5.3.1, mitre-T1195.002, mitre-T1078, cwe-494, cwe-345, nist-csf-pr.ds-6, nist-csf-id.sc-3, nist-800-53-si-7, nist-800-53-sr-4, csa-ccm-ais-04, csa-ccm-tvm-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-K8S-HELM-003 \u2014 helm_release weak supply-chain controls (`verify = false` OR `version` unpinned)",
  "description": "Pin `version` to an exact semver and enable signature verification\nagainst a known-good keyring. For OCI registries that don't ship\nPGP keyrings, pair `version` pinning with a private mirror so the\napply path doesn't reach the upstream regi",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-HELM-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-HELM-003/"
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
  "keywords": "security, high, terraform, CIS 5.3.1, MITRE T1195.002, MITRE T1078, CWE-494, CWE-345",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-K8S-HELM-003 — helm_release weak supply-chain controls (`verify = false` OR `version` unpinned)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-K8S-HELM-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-K8S-HELM-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-K8S-HELM-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **helm_release weak supply-chain controls (`verify = false` OR `version` unpinned).** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_body_contains`** on `helm_release` matching `/(?m)^\s*verify\s*=\s*false\b/` — _the resource body matches a regex inside the block._
  `helm_release` sets `verify = false` (or relies on the provider
default, which is off). Without chart signature verification a
compromised or typosquatted chart repository serves an attacker
arbitrary Kubernetes manifests on `terraform apply`. The 2021
Codecov compromise and the 2023 3CX supply-chain incident both
pivoted through unsigned build-time artefacts; helm charts are
the equivalent surface for cluster workloads.
2. **`resource_missing_arg`** on `helm_release` (`version`) — _the resource is missing a required attribute (or nested attribute path)._
  `helm_release` omits `version` entirely. The chart resolves to
the repository's *current* latest tag on every `terraform apply`,
so the deployed manifests can change without any diff in the
Terraform configuration. An attacker who compromises the chart
repository (or a maintainer's credentials) pushes a new "latest"
and the next apply pulls it silently.

## Why it likely fired

`helm_release` sets `verify = false` (or relies on the provider
default, which is off). Without chart signature verification a
compromised or typosquatted chart repository serves an attacker
arbitrary Kubernetes manifests on `terraform apply`. The 2021
Codecov compromise and the 2023 3CX supply-chain incident both
pivoted through unsigned build-time artefacts; helm charts are
the equivalent surface for cluster workloads.

`helm_release` omits `version` entirely. The chart resolves to
the repository's *current* latest tag on every `terraform apply`,
so the deployed manifests can change without any diff in the
Terraform configuration. An attacker who compromises the chart
repository (or a maintainer's credentials) pushes a new "latest"
and the next apply pulls it silently.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-HELM-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Pin `version` to an exact semver and enable signature verification
against a known-good keyring. For OCI registries that don't ship
PGP keyrings, pair `version` pinning with a private mirror so the
apply path doesn't reach the upstream registry at all.

    resource "helm_release" "app" {
      name       = "app"
      repository = "https://charts.example.io"
      chart      = "app"
      version    = "1.4.2"
      verify     = true
      keyring    = "/etc/helm/keyring.gpg"
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "helm_release" "example" {
  name       = "example"
  repository = "https://charts.example.io"
  chart      = "example"
  version    = "1.4.2"
  verify     = true
  keyring    = "/etc/helm/keyring.gpg"
}
```

_Enabling `verify` and pinning `version` may fail the next apply if the keyring is missing or the chart was floating. Stage the keyring first, then bump version._

## Verification

```sh
`helm verify <chart>` against every chart referenced from
`helm_release` blocks must succeed against the chosen keyring;
`terraform state list | xargs -n1 terraform state show | grep helm_release`
must not show any release without a pinned `version`.
```

## References

**CIS Benchmark**
  - `CIS 5.3.1`

**PCI-DSS**
  - `Req-6.4.5`

**SOC 2 Trust Services Criteria**
  - `CC8.1`

**OWASP IaC Cheat Sheet**
  - [`Develop and Distribute / Image Signing`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)
  - [`T1078`](https://attack.mitre.org/techniques/T1078/)

**CWE**
  - [`CWE-494`](https://cwe.mitre.org/data/definitions/494.html)
  - [`CWE-345`](https://cwe.mitre.org/data/definitions/345.html)

**NIST CSF 2.0**
  - [`PR.DS-6`](https://www.nist.gov/cyberframework)
  - [`ID.SC-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SI-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=si-7)
  - [`SR-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-4)

**CSA CCM v4**
  - [`AIS-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
  - [`TVM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**OWASP (namespaced)**
  - `K05`

**Source**
  - [`catalog/SEC-K8S-HELM-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-HELM-003.yaml) — canonical YAML

## Family

See also rules in the `SEC-K8S-HELM-*` family:

- [`SEC-K8S-HELM-001`](./SEC-K8S-HELM-001.md) — helm_release sets `service.type=LoadBalancer` (publicly exposed)
- [`SEC-K8S-HELM-002`](./SEC-K8S-HELM-002.md) — helm_release sets `securityContext.privileged=true`
- [`SEC-K8S-HELM-004`](./SEC-K8S-HELM-004.md) — helm_release bypasses chart safety (`disable_webhooks = true` OR `skip_crds = true`)

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-HELM-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-HELM-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-HELM-003
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
