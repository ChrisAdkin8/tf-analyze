# ⚠️ SEC-K8S-NETPOL-001 — kubernetes_network_policy absent for the corpus

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **kubernetes_network_policy absent for the corpus.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_absent`** on `kubernetes_network_policy` — _the corpus is missing a resource type we expected to find given other resources present._
  The corpus declares `kubernetes_namespace` resources but no
`kubernetes_network_policy`. Without a NetworkPolicy every pod
can reach every other pod on every port — there is no
default-deny. An attacker who compromises one container scans
and pivots laterally without traversing any network barrier
(the 2018 Tesla cryptomining incident exploited exactly this).

## Why it likely fired

The corpus declares `kubernetes_namespace` resources but no
`kubernetes_network_policy`. Without a NetworkPolicy every pod
can reach every other pod on every port — there is no
default-deny. An attacker who compromises one container scans
and pivots laterally without traversing any network barrier
(the 2018 Tesla cryptomining incident exploited exactly this).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-NETPOL-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Ship at minimum a default-deny egress + ingress policy in every
workload namespace, then layer specific allow rules on top:

    resource "kubernetes_network_policy" "default_deny" {
      metadata {
        name      = "default-deny"
        namespace = kubernetes_namespace.app.metadata[0].name
      }
      spec {
        pod_selector {}
        policy_types = ["Ingress", "Egress"]
      }
    }

Then add `allow-dns`, `allow-from-ingress-controller`, etc. as
separate policies that opt in.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "kubernetes_network_policy" "default_deny" {
  metadata {
    name      = "default-deny"
    namespace = kubernetes_namespace.app.metadata[0].name
  }
  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}
```

_Default-deny will break running traffic until allow rules are added. Roll out per-namespace in audit before enforce._

## Verification

```sh
`kubectl get networkpolicy -A` must return at least one policy per
workload namespace; `kubectl describe ns <name> | grep network`
should not be empty.
```

## References

**CIS Benchmark**
  - `CIS 5.3.2`

**PCI-DSS**
  - `Req-1.2`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1611`](https://attack.mitre.org/techniques/T1611/)

**Source**
  - [`catalog/SEC-K8S-NETPOL-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-NETPOL-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-NETPOL-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-NETPOL-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-NETPOL-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
