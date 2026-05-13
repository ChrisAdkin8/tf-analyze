---
title: "SEC-K8S-HELM-004 — helm_release bypasses chart safety (`disable_webhooks = true` OR `skip_crds = true`)"
description: "tf-analyze rule SEC-K8S-HELM-004 (HIGH · security): helm_release bypasses chart safety (`disable_webhooks = true` OR `skip_crds = true`)"
keywords: "security, high, terraform, iac, cis-5.2.4, mitre-T1562.001, mitre-T1078, cwe-693, cwe-1188, nist-csf-pr.ip-1, nist-csf-pr.pt-3, nist-800-53-cm-7, nist-800-53-si-7, csa-ccm-ccc-04, csa-ccm-tvm-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-K8S-HELM-004 \u2014 helm_release bypasses chart safety (`disable_webhooks = true` OR `skip_crds = true`)",
  "description": "Remove the bypass flag. If a webhook or CRD is genuinely the\nblocking factor, fix the upstream issue rather than disabling the\nsafety net:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-HELM-004/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-HELM-004/"
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
  "keywords": "security, high, terraform, CIS 5.2.4, MITRE T1562.001, MITRE T1078, CWE-693, CWE-1188",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-K8S-HELM-004 — helm_release bypasses chart safety (`disable_webhooks = true` OR `skip_crds = true`)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-K8S-HELM-004" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-K8S-HELM-004" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-K8S-HELM-004 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **helm_release bypasses chart safety (`disable_webhooks = true` OR `skip_crds = true`).** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_body_contains`** on `helm_release` matching `/(?m)^\s*disable_webhooks\s*=\s*true\b/` — _the resource body matches a regex inside the block._
  `helm_release` sets `disable_webhooks = true`, bypassing pre-install
and post-install admission webhooks. Charts often use webhooks
to enforce field defaults, validate resource combinations, and
stage TLS-cert generation — skipping them leaves the release
in an unsafe interim state that the chart author never tested.
2. **`resource_body_contains`** on `helm_release` matching `/(?m)^\s*skip_crds\s*=\s*true\b/` — _the resource body matches a regex inside the block._
  `helm_release` sets `skip_crds = true`, bypassing the chart's
CRD installation. Any subsequent resource that references those
CRDs (e.g. a CertManager `Certificate` or an Istio `VirtualService`)
will be scheduled before the CRD exists, producing apply-time
races. The cert-manager and OPA Gatekeeper communities both
explicitly document `skip_crds` as a footgun.

## Why it likely fired

`helm_release` sets `disable_webhooks = true`, bypassing pre-install
and post-install admission webhooks. Charts often use webhooks
to enforce field defaults, validate resource combinations, and
stage TLS-cert generation — skipping them leaves the release
in an unsafe interim state that the chart author never tested.

`helm_release` sets `skip_crds = true`, bypassing the chart's
CRD installation. Any subsequent resource that references those
CRDs (e.g. a CertManager `Certificate` or an Istio `VirtualService`)
will be scheduled before the CRD exists, producing apply-time
races. The cert-manager and OPA Gatekeeper communities both
explicitly document `skip_crds` as a footgun.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-HELM-004` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove the bypass flag. If a webhook or CRD is genuinely the
blocking factor, fix the upstream issue rather than disabling the
safety net:

- Webhook 503/timeout: increase `wait_for_jobs` and `timeout`;
  investigate why the cluster's webhook serving pod is unhealthy.
- CRD already exists from a previous install: the correct shape is
  to let Helm manage the CRD lifecycle from a single release, not
  to skip it.

    resource "helm_release" "app" {
      name             = "app"
      repository       = "https://charts.example.io"
      chart            = "app"
      version          = "1.4.2"
      disable_webhooks = false   # default; included for explicitness
      skip_crds        = false
      wait             = true
      wait_for_jobs    = true
      timeout          = 600
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "helm_release" "example" {
  name             = "example"
  repository       = "https://charts.example.io"
  chart            = "example"
  version          = "1.4.2"
  disable_webhooks = false
  skip_crds        = false
  wait             = true
  wait_for_jobs    = true
  timeout          = 600
}
```

_Removing `disable_webhooks` or `skip_crds` may cause the next apply to fail if the underlying issue (unhealthy webhook, pre-existing CRDs) hasn't been fixed first. Investigate the original reason the flag was set before removing it._

## Verification

```sh
`terraform state list | grep helm_release | xargs -I{} terraform state show {} | grep -E '(disable_webhooks|skip_crds) *= *true'`
should return empty for every workload release.
```

## References

**CIS Benchmark**
  - `CIS 5.2.4`

**PCI-DSS**
  - `Req-6.4.2`

**SOC 2 Trust Services Criteria**
  - `CC8.1`

**MITRE ATT&CK**
  - [`T1562.001`](https://attack.mitre.org/techniques/T1562/001/)
  - [`T1078`](https://attack.mitre.org/techniques/T1078/)

**CWE**
  - [`CWE-693`](https://cwe.mitre.org/data/definitions/693.html)
  - [`CWE-1188`](https://cwe.mitre.org/data/definitions/1188.html)

**NIST CSF 2.0**
  - [`PR.IP-1`](https://www.nist.gov/cyberframework)
  - [`PR.PT-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CM-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cm-7)
  - [`SI-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=si-7)

**CSA CCM v4**
  - [`CCC-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
  - [`TVM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**OWASP (namespaced)**
  - `K07`

**Source**
  - [`catalog/SEC-K8S-HELM-004.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-HELM-004.yaml) — canonical YAML

## Family

See also rules in the `SEC-K8S-HELM-*` family:

- [`SEC-K8S-HELM-001`](./SEC-K8S-HELM-001.md) — helm_release sets `service.type=LoadBalancer` (publicly exposed)
- [`SEC-K8S-HELM-002`](./SEC-K8S-HELM-002.md) — helm_release sets `securityContext.privileged=true`
- [`SEC-K8S-HELM-003`](./SEC-K8S-HELM-003.md) — helm_release weak supply-chain controls (`verify = false` OR `version` unpinned)

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-HELM-004    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-HELM-004` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-HELM-004
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
