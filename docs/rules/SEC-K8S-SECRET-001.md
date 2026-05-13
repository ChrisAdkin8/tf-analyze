---
title: "SEC-K8S-SECRET-001 — kubernetes_secret carries literal `data` (vs ExternalSecret / Vault Secrets Operator)"
description: "tf-analyze rule SEC-K8S-SECRET-001 (HIGH · security): kubernetes_secret carries literal `data` (vs ExternalSecret / Vault Secrets Operator)"
keywords: "security, high, terraform, iac, cis-5.4.1, mitre-T1552.001, mitre-T1078, cwe-798, cwe-312, nist-csf-pr.ds-1, nist-csf-pr.ds-5, nist-800-53-ia-5, nist-800-53-sc-28, csa-ccm-ekm-04, csa-ccm-dsi-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-K8S-SECRET-001 \u2014 kubernetes_secret carries literal `data` (vs ExternalSecret / Vault Secrets Operator)",
  "description": "Replace the literal `data` with a Kubernetes Secrets Operator\nreference. Two common patterns:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-SECRET-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-SECRET-001/"
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
  "keywords": "security, high, terraform, CIS 5.4.1, MITRE T1552.001, MITRE T1078, CWE-798, CWE-312",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-K8S-SECRET-001 — kubernetes_secret carries literal `data` (vs ExternalSecret / Vault Secrets Operator)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-K8S-SECRET-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-K8S-SECRET-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-K8S-SECRET-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **kubernetes_secret carries literal `data` (vs ExternalSecret / Vault Secrets Operator).** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_body_contains`** on `kubernetes_secret` matching `/(?m)^\s*data\s*=\s*\{/` — _the resource body matches a regex inside the block._
  `kubernetes_secret` has a literal `data = { ... }` map. The
values are base64-encoded but not encrypted — they're stored
verbatim in the .tf source and the Terraform state file. The
2019 Capital One breach and the 2023 CircleCI compromise both
exfiltrated secrets from artefacts that operators believed
were "encoded" (base64) rather than "encrypted".
2. **`resource_body_contains`** on `kubernetes_secret` matching `/(?m)^\s*data\s*\{/` — _the resource body matches a regex inside the block._
  Same as above using the block form (`data { foo = "..." }`)
rather than the map form (`data = { foo = "..." }`). Both
shapes embed the literal value in source and state.
3. **`resource_body_contains`** on `kubernetes_secret_v1` matching `/(?m)^\s*data\s*=\s*\{/` — _the resource body matches a regex inside the block._
  `kubernetes_secret_v1` is the API-versioned alias of the same
resource — same literal-data anti-pattern.

## Why it likely fired

`kubernetes_secret` has a literal `data = { ... }` map. The
values are base64-encoded but not encrypted — they're stored
verbatim in the .tf source and the Terraform state file. The
2019 Capital One breach and the 2023 CircleCI compromise both
exfiltrated secrets from artefacts that operators believed
were "encoded" (base64) rather than "encrypted".

Same as above using the block form (`data { foo = "..." }`)
rather than the map form (`data = { foo = "..." }`). Both
shapes embed the literal value in source and state.

`kubernetes_secret_v1` is the API-versioned alias of the same
resource — same literal-data anti-pattern.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-SECRET-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace the literal `data` with a Kubernetes Secrets Operator
reference. Two common patterns:

External Secrets Operator (ESO) — Terraform declares the
ExternalSecret CRD; ESO pulls the value from Vault / Secrets
Manager / GCP Secret Manager at runtime:

    resource "kubernetes_manifest" "db_password" {
      manifest = {
        apiVersion = "external-secrets.io/v1beta1"
        kind       = "ExternalSecret"
        metadata = { name = "db-password", namespace = "app" }
        spec = {
          secretStoreRef = { name = "vault", kind = "ClusterSecretStore" }
          target         = { name = "db-password" }
          data = [{
            secretKey = "password"
            remoteRef = { key = "kv/data/app", property = "db_password" }
          }]
        }
      }
    }

Vault Secrets Operator (VSO) — same shape, vault-native:

    resource "kubernetes_manifest" "vso" {
      manifest = {
        apiVersion = "secrets.hashicorp.com/v1beta1"
        kind       = "VaultStaticSecret"
        metadata = { name = "db", namespace = "app" }
        spec = {
          mount     = "kv"
          type      = "kv-v2"
          path      = "app/db"
          destination = { create = true, name = "db" }
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "kubernetes_manifest" "external_secret" {
  manifest = {
    apiVersion = "external-secrets.io/v1beta1"
    kind       = "ExternalSecret"
    metadata = {
      name      = "app-secret"
      namespace = "app"
    }
    spec = {
      secretStoreRef = {
        name = "vault"
        kind = "ClusterSecretStore"
      }
      target = {
        name           = "app-secret"
        creationPolicy = "Owner"
      }
      data = [{
        secretKey = "password"
        remoteRef = {
          key      = "kv/data/app"
          property = "password"
        }
      }]
    }
  }
}
```

_Replacing kubernetes_secret with an ExternalSecret deletes the Terraform-managed Secret and lets ESO recreate it from Vault. Pods using the secret will momentarily lose access; stage in a sidecar namespace first._

## Verification

```sh
`terraform state list | grep kubernetes_secret$ | while read r; do terraform state show "$r" | grep -A2 '"data"'; done`
should not show literal values — only references via env vars or
external secrets-operator CRDs.
```

## References

**CIS Benchmark**
  - `CIS 5.4.1`

**PCI-DSS**
  - `Req-3.5.1`
  - `Req-8.3.1`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**OWASP IaC Cheat Sheet**
  - [`Develop and Distribute / Secrets Detection`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)
  - [`T1078`](https://attack.mitre.org/techniques/T1078/)

**CWE**
  - [`CWE-798`](https://cwe.mitre.org/data/definitions/798.html)
  - [`CWE-312`](https://cwe.mitre.org/data/definitions/312.html)

**NIST CSF 2.0**
  - [`PR.DS-1`](https://www.nist.gov/cyberframework)
  - [`PR.DS-5`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`IA-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ia-5)
  - [`SC-28`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-28)

**CSA CCM v4**
  - [`EKM-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
  - [`DSI-03`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**OWASP (namespaced)**
  - `K08`

**Source**
  - [`catalog/SEC-K8S-SECRET-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-SECRET-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-K8S-SECRET-*` family:

- [`SEC-K8S-SECRET-002`](./SEC-K8S-SECRET-002.md) — kubernetes_secret of type `kubernetes.io/dockerconfigjson` carries literal data (image-pull credentials in state)

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-SECRET-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-SECRET-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-SECRET-001
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
