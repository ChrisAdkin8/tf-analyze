# ⚠️ SEC-K8S-PSA-001 — kubernetes_namespace missing Pod Security Admission label

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **kubernetes_namespace missing Pod Security Admission label.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `kubernetes_namespace` (`metadata.labels`) — _the resource is missing a required attribute (or nested attribute path)._
  `kubernetes_namespace` block has no `metadata.labels` (or labels
without `pod-security.kubernetes.io/enforce`). Without a Pod
Security Admission level, the namespace defaults to no enforcement
— privileged pods, hostPath mounts, and host-network pods are all
permitted. PSA replaced the deprecated PodSecurityPolicy in 1.25.

## Why it likely fired

`kubernetes_namespace` block has no `metadata.labels` (or labels
without `pod-security.kubernetes.io/enforce`). Without a Pod
Security Admission level, the namespace defaults to no enforcement
— privileged pods, hostPath mounts, and host-network pods are all
permitted. PSA replaced the deprecated PodSecurityPolicy in 1.25.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-PSA-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add the PSA enforcement label to every namespace, scoped to the
least-privileged level the workload tolerates:

    resource "kubernetes_namespace" "app" {
      metadata {
        name = "app"
        labels = {
          "pod-security.kubernetes.io/enforce"         = "restricted"
          "pod-security.kubernetes.io/enforce-version" = "latest"
        }
      }
    }

Use `baseline` for legacy workloads that still need privileged
capabilities; `restricted` is the right default for new workloads.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "kubernetes_namespace" "example" {
  metadata {
    name = "example"
    labels = {
      "pod-security.kubernetes.io/enforce"         = "restricted"
      "pod-security.kubernetes.io/enforce-version" = "latest"
    }
  }
}
```

_Tightening PSA on a running namespace can reject pending pods that violate the level. Roll out in audit mode first._

## Verification

```sh
`kubectl get ns -o jsonpath='{.items[*].metadata.labels.pod-security\.kubernetes\.io/enforce}'`
must list a level for every non-system namespace.
```

## References

**CIS Benchmark**
  - `CIS 5.2.1`

**PCI-DSS**
  - `Req-2.2`

**SOC 2 Trust Services Criteria**
  - `CC6.6`

**MITRE ATT&CK**
  - [`T1611`](https://attack.mitre.org/techniques/T1611/)

**Source**
  - [`catalog/SEC-K8S-PSA-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-PSA-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-PSA-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-PSA-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-PSA-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
