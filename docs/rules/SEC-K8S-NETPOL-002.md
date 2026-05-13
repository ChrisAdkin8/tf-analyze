---
title: "SEC-K8S-NETPOL-002 — kubernetes_network_policy is overly permissive (0.0.0.0/0 cidr OR empty rule)"
description: "tf-analyze rule SEC-K8S-NETPOL-002 (HIGH · security): kubernetes_network_policy is overly permissive (0.0.0.0/0 cidr OR empty rule)"
keywords: "security, high, terraform, iac, cis-5.3.2, mitre-T1190, mitre-T1041, cwe-284, cwe-1188, nist-csf-pr.ac-5, nist-800-53-sc-7, nist-800-53-ac-4, csa-ccm-ivs-06, csa-ccm-ivs-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-K8S-NETPOL-002 \u2014 kubernetes_network_policy is overly permissive (0.0.0.0/0 cidr OR empty rule)",
  "description": "Replace the wildcard cidr with the specific CIDR(s) the workload\nneeds to reach. If the workload genuinely needs egress to the\npublic internet, route it through an egress proxy / NAT gateway\nand whitelist that proxy's IP \u2014 never the full `0",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-NETPOL-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-NETPOL-002/"
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
  "keywords": "security, high, terraform, CIS 5.3.2, MITRE T1190, MITRE T1041, CWE-284, CWE-1188",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-K8S-NETPOL-002 — kubernetes_network_policy is overly permissive (0.0.0.0/0 cidr OR empty rule)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-K8S-NETPOL-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-K8S-NETPOL-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-K8S-NETPOL-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **kubernetes_network_policy is overly permissive (0.0.0.0/0 cidr OR empty rule).** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_body_contains`** on `kubernetes_network_policy` matching `/cidr\s*=\s*"0\.0\.0\.0/0"/` — _the resource body matches a regex inside the block._
  `kubernetes_network_policy` whitelists `0.0.0.0/0` in an `ip_block`.
Every IPv4 address — including the public internet — matches the
rule. The 2018 Tesla / Kubernetes-dashboard cryptomining incident
pivoted through exactly this shape: a "network policy is
configured" cluster whose policy whitelisted the world.
2. **`resource_body_contains`** on `kubernetes_network_policy` matching `/(?ms)^\s*egress\s*\{\s*\}/` — _the resource body matches a regex inside the block._
  `kubernetes_network_policy` has an empty `egress { }` block. An
empty rule in NetworkPolicy semantics is "allow all" — every
egress destination is permitted from pods this policy selects.
The cluster operator probably intended `egress { }` to mean
"deny all egress", which is a common mistranslation from iptables
mental models.
3. **`resource_body_contains`** on `kubernetes_network_policy` matching `/(?ms)^\s*ingress\s*\{\s*\}/` — _the resource body matches a regex inside the block._
  Same as above on the ingress side — `ingress { }` resolves to
"allow all" inbound, defeating the purpose of a NetworkPolicy.
4. **`resource_body_contains`** on `kubernetes_network_policy_v1` matching `/cidr\s*=\s*"0\.0\.0\.0/0"/` — _the resource body matches a regex inside the block._
  API-versioned alias — same anti-pattern.

## Why it likely fired

`kubernetes_network_policy` whitelists `0.0.0.0/0` in an `ip_block`.
Every IPv4 address — including the public internet — matches the
rule. The 2018 Tesla / Kubernetes-dashboard cryptomining incident
pivoted through exactly this shape: a "network policy is
configured" cluster whose policy whitelisted the world.

`kubernetes_network_policy` has an empty `egress { }` block. An
empty rule in NetworkPolicy semantics is "allow all" — every
egress destination is permitted from pods this policy selects.
The cluster operator probably intended `egress { }` to mean
"deny all egress", which is a common mistranslation from iptables
mental models.

Same as above on the ingress side — `ingress { }` resolves to
"allow all" inbound, defeating the purpose of a NetworkPolicy.

API-versioned alias — same anti-pattern.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-NETPOL-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace the wildcard cidr with the specific CIDR(s) the workload
needs to reach. If the workload genuinely needs egress to the
public internet, route it through an egress proxy / NAT gateway
and whitelist that proxy's IP — never the full `0.0.0.0/0`. Empty
rule blocks should be deleted (the policy itself + `policy_types`
decides direction, an empty rule is never the right shape).

    resource "kubernetes_network_policy" "app" {
      metadata {
        name      = "app"
        namespace = "app"
      }
      spec {
        pod_selector { match_labels = { app = "app" } }
        policy_types = ["Egress"]
        egress {
          to {
            ip_block {
              cidr   = "10.0.0.0/16"
              except = ["10.0.100.0/24"]
            }
          }
          ports {
            protocol = "TCP"
            port     = "5432"
          }
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "kubernetes_network_policy" "scoped" {
  metadata {
    name      = "scoped"
    namespace = "app"
  }
  spec {
    pod_selector { match_labels = { app = "app" } }
    policy_types = ["Egress"]
    egress {
      to {
        ip_block {
          cidr = "10.0.0.0/16"
        }
      }
      ports {
        protocol = "TCP"
        port     = "5432"
      }
    }
  }
}
```

_Tightening from allow-all to a specific cidr will break any workload that depended on reaching destinations outside the whitelist. Roll out alongside an egress-traffic dashboard so unexpected drops surface immediately._

## Verification

```sh
`kubectl get networkpolicy -A -o json | jq '.items[] | select(.spec.egress[]?.to[]?.ipBlock?.cidr == "0.0.0.0/0" or .spec.egress[]? == {} or .spec.ingress[]? == {})'`
should return empty across non-bootstrap namespaces.
```

## References

**CIS Benchmark**
  - `CIS 5.3.2`

**PCI-DSS**
  - `Req-1.2`
  - `Req-1.3`

**SOC 2 Trust Services Criteria**
  - `CC6.6`

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)
  - [`T1041`](https://attack.mitre.org/techniques/T1041/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)
  - [`CWE-1188`](https://cwe.mitre.org/data/definitions/1188.html)

**NIST CSF 2.0**
  - [`PR.AC-5`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-7)
  - [`AC-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-4)

**CSA CCM v4**
  - [`IVS-06`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
  - [`IVS-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**OWASP (namespaced)**
  - `K06`

**Source**
  - [`catalog/SEC-K8S-NETPOL-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-NETPOL-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-K8S-NETPOL-*` family:

- [`SEC-K8S-NETPOL-001`](./SEC-K8S-NETPOL-001.md) — kubernetes_network_policy absent for the corpus

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-NETPOL-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-NETPOL-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-NETPOL-002
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
