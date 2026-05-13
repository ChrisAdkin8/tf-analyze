---
title: "SEC-K8S-SECRET-002 — kubernetes_secret of type `kubernetes.io/dockerconfigjson` carries literal data (image-pull credentials in state)"
description: "tf-analyze rule SEC-K8S-SECRET-002 (CRITICAL · security): kubernetes_secret of type `kubernetes.io/dockerconfigjson` carries literal data (image-pull crede…"
keywords: "security, critical, terraform, iac, cis-5.4.1, mitre-T1552.001, mitre-T1525, mitre-T1195.002, cwe-798, cwe-312, nist-csf-pr.ds-1, nist-csf-id.sc-3, nist-800-53-ia-5, nist-800-53-sr-3, csa-ccm-ekm-04, csa-ccm-tvm-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-K8S-SECRET-002 \u2014 kubernetes_secret of type `kubernetes.io/dockerconfigjson` carries literal data (image-pull credentials in state)",
  "description": "Replace the literal `.dockerconfigjson` with a cloud-native\nworkload-identity flow that gives pods short-lived credentials\nto the registry, with no Kubernetes Secret in the path:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-SECRET-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-SECRET-002/"
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
  "keywords": "security, critical, terraform, CIS 5.4.1, MITRE T1552.001, MITRE T1525, MITRE T1195.002, CWE-798, CWE-312",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-K8S-SECRET-002 — kubernetes_secret of type `kubernetes.io/dockerconfigjson` carries literal data (image-pull credentials in state)

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-K8S-SECRET-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-K8S-SECRET-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-K8S-SECRET-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **kubernetes_secret of type `kubernetes.io/dockerconfigjson` carries literal data (image-pull credentials in state).** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`resource_body_contains`** on `kubernetes_secret` matching `/(?ms)type\s*=\s*"kubernetes\.io/dockerconfigjson".*?\.dockerconfigjson"?\s*=/` — _the resource body matches a regex inside the block._
  `kubernetes_secret` declares `type = "kubernetes.io/dockerconfigjson"`
and carries a literal `.dockerconfigjson` payload in `data`. The
payload is the base64-encoded contents of `~/.docker/config.json` —
i.e. registry username + password (or OAuth token) for every
registry the workload pulls from. The 2024 Sisense breach and
the 2023 CircleCI compromise both exfiltrated registry credentials
from artefacts that operators thought were "encoded".
2. **`resource_body_contains`** on `kubernetes_secret_v1` matching `/(?ms)type\s*=\s*"kubernetes\.io/dockerconfigjson".*?\.dockerconfigjson"?\s*=/` — _the resource body matches a regex inside the block._
  API-versioned alias — same anti-pattern.

## Why it likely fired

`kubernetes_secret` declares `type = "kubernetes.io/dockerconfigjson"`
and carries a literal `.dockerconfigjson` payload in `data`. The
payload is the base64-encoded contents of `~/.docker/config.json` —
i.e. registry username + password (or OAuth token) for every
registry the workload pulls from. The 2024 Sisense breach and
the 2023 CircleCI compromise both exfiltrated registry credentials
from artefacts that operators thought were "encoded".

API-versioned alias — same anti-pattern.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-SECRET-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace the literal `.dockerconfigjson` with a cloud-native
workload-identity flow that gives pods short-lived credentials
to the registry, with no Kubernetes Secret in the path:

- **GKE:** Workload Identity + Artifact Registry Reader IAM. Pods
  pull via the node's identity; no docker-config secret exists.
- **EKS:** IRSA + ECR Read IAM. Same shape.
- **AKS:** Workload Identity + AcrPull role.

Where workload identity is genuinely unavailable (e.g. air-gapped
installs), use an External Secrets Operator ExternalSecret pulling
from Vault / Cloud Secret Manager so the literal credential never
lives in source or state:

    resource "kubernetes_manifest" "pull_creds" {
      manifest = {
        apiVersion = "external-secrets.io/v1beta1"
        kind       = "ExternalSecret"
        metadata = { name = "pull-creds", namespace = "app" }
        spec = {
          secretStoreRef = { name = "vault", kind = "ClusterSecretStore" }
          target         = { name = "pull-creds", template = { type = "kubernetes.io/dockerconfigjson" } }
          data = [{
            secretKey = ".dockerconfigjson"
            remoteRef = { key = "kv/data/registry", property = "dockerconfigjson" }
          }]
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "kubernetes_manifest" "image_pull_secret" {
  manifest = {
    apiVersion = "external-secrets.io/v1beta1"
    kind       = "ExternalSecret"
    metadata = {
      name      = "pull-creds"
      namespace = "app"
    }
    spec = {
      secretStoreRef = {
        name = "vault"
        kind = "ClusterSecretStore"
      }
      target = {
        name           = "pull-creds"
        creationPolicy = "Owner"
        template = {
          type = "kubernetes.io/dockerconfigjson"
        }
      }
      data = [{
        secretKey = ".dockerconfigjson"
        remoteRef = {
          key      = "kv/data/registry"
          property = "dockerconfigjson"
        }
      }]
    }
  }
}
```

_Replacing the in-state dockerconfigjson with an ExternalSecret means pods will momentarily fail to pull until ESO reconciles. Rotate the registry credential *after* the migration — the in-state copy must be assumed leaked._

## Verification

```sh
`terraform state list | grep '^kubernetes_secret\.' | xargs -I {} terraform state show {} | awk '/type *= "kubernetes.io\\/dockerconfigjson"/{found=1} found && /\\.dockerconfigjson *=/{print FILENAME; found=0}'`
should return empty. Better: run `terraform state pull | grep -c dockerconfigjson` and expect 0.
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
  - [`T1525`](https://attack.mitre.org/techniques/T1525/)
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-798`](https://cwe.mitre.org/data/definitions/798.html)
  - [`CWE-312`](https://cwe.mitre.org/data/definitions/312.html)

**NIST CSF 2.0**
  - [`PR.DS-1`](https://www.nist.gov/cyberframework)
  - [`ID.SC-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`IA-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ia-5)
  - [`SR-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-3)

**CSA CCM v4**
  - [`EKM-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
  - [`TVM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**OWASP (namespaced)**
  - `K08`

**Source**
  - [`catalog/SEC-K8S-SECRET-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-SECRET-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-K8S-SECRET-*` family:

- [`SEC-K8S-SECRET-001`](./SEC-K8S-SECRET-001.md) — kubernetes_secret carries literal `data` (vs ExternalSecret / Vault Secrets Operator)

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-SECRET-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-SECRET-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-SECRET-002
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
