# 🚨 SEC-K8S-RBAC-001 — ClusterRoleBinding grants cluster-admin

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **ClusterRoleBinding grants cluster-admin.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`resource_body_contains`** on `kubernetes_cluster_role_binding` matching `/name\s*=\s*"cluster-admin"/` — _the resource body matches a regex inside the block._
  `kubernetes_cluster_role_binding` references the built-in
`cluster-admin` ClusterRole. Any subject bound to this binding
(ServiceAccount, User, Group) has full unrestricted access to
every API across every namespace — equivalent to root on every
node. Compromise of any pod or token bound through this binding
yields full cluster takeover.

## Why it likely fired

`kubernetes_cluster_role_binding` references the built-in
`cluster-admin` ClusterRole. Any subject bound to this binding
(ServiceAccount, User, Group) has full unrestricted access to
every API across every namespace — equivalent to root on every
node. Compromise of any pod or token bound through this binding
yields full cluster takeover.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-RBAC-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace the cluster-admin reference with a scoped ClusterRole or a
namespaced RoleBinding. If absolute-power access is genuinely
required (rare; usually only for cluster operators), keep the
binding short-lived and attach it to a specific User identity, not
a long-lived ServiceAccount.

    resource "kubernetes_role_binding" "app" {
      metadata {
        name      = "app"
        namespace = "app"
      }
      role_ref {
        api_group = "rbac.authorization.k8s.io"
        kind      = "ClusterRole"
        name      = "view"   # scoped, read-only
      }
      subject {
        kind      = "ServiceAccount"
        name      = "app"
        namespace = "app"
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "kubernetes_role_binding" "scoped" {
  metadata {
    name      = "app-scoped"
    namespace = "app"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "view"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "app"
    namespace = "app"
  }
}
```

_Replacing the binding is destructive — pods using the previous role will lose access until rebound. Stage the new binding alongside, migrate workloads, then delete the old one._

## Verification

```sh
`kubectl get clusterrolebindings -o jsonpath='{.items[?(@.roleRef.name=="cluster-admin")].subjects[*].name}'`
should not include any ServiceAccount in a workload namespace.
```

## References

**CIS Benchmark**
  - `CIS 5.1.1`

**PCI-DSS**
  - `Req-7.2.2`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)
  - [`T1098.001`](https://attack.mitre.org/techniques/T1098/001/)

**Source**
  - [`catalog/SEC-K8S-RBAC-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-RBAC-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-RBAC-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-RBAC-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-RBAC-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
