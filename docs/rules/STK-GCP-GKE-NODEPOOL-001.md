---
title: "STK-GCP-GKE-NODEPOOL-001 — GKE node pool missing shielded-instance hardening"
description: "tf-analyze rule STK-GCP-GKE-NODEPOOL-001 (HIGH · stack): GKE node pool missing shielded-instance hardening"
keywords: "stack, high, terraform, iac, gcp, cis-6.5.5, mitre-T1542.003, cwe-1278, d3-psh"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-GKE-NODEPOOL-001 \u2014 GKE node pool missing shielded-instance hardening",
  "description": "Add to each `google_container_node_pool`:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-GKE-NODEPOOL-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-GKE-NODEPOOL-001/"
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
  "keywords": "stack, high, terraform, CIS 6.5.5, MITRE T1542.003, CWE-1278, D3-PSH",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-GCP-GKE-NODEPOOL-001 — GKE node pool missing shielded-instance hardening

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-GKE-NODEPOOL-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-GKE-NODEPOOL-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-GKE-NODEPOOL-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GKE node pool missing shielded-instance hardening.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`graph_check`** — _a corpus-wide graph check fired (cross-resource invariant)._
  Every `google_container_node_pool` attached to a cluster must set
`node_config.shielded_instance_config.enable_secure_boot = true` AND
`enable_integrity_monitoring = true`. Pods schedule across pools, so
one unhardened pool nullifies the cluster-wide posture.

## Why it likely fired

Every `google_container_node_pool` attached to a cluster must set
`node_config.shielded_instance_config.enable_secure_boot = true` AND
`enable_integrity_monitoring = true`. Pods schedule across pools, so
one unhardened pool nullifies the cluster-wide posture.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-GKE-NODEPOOL-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add to each `google_container_node_pool`:

    node_config {
      shielded_instance_config {
        enable_secure_boot          = true
        enable_integrity_monitoring = true
      }
    }

Then re-create the pool — `node_config` changes force replacement, so
schedule the cycle during a maintenance window or use surge upgrades.

Tip: enforce this at cluster level via Org Policy
`constraints/container.requireShieldedNodes`. The Terraform finding then
becomes a defense-in-depth check rather than the only line of defense.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_container_node_pool" "example" {
  name       = "example"
  cluster    = google_container_cluster.example.id
  location   = "us-central1"
  node_config {
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }
}
```

## Verification

After applying, run:

    gcloud container node-pools describe <pool> \\
      --cluster=<cluster> --region=<region> \\
      --format='value(config.shieldedInstanceConfig.enableSecureBoot,config.shieldedInstanceConfig.enableIntegrityMonitoring)'

Both fields should print `True`. Re-run tf-analyze to confirm clean.

## References

**CIS Benchmark**
  - `CIS 6.5.5`

**MITRE ATT&CK**
  - [`T1542.003`](https://attack.mitre.org/techniques/T1542/003/)

**CWE**
  - [`CWE-1278`](https://cwe.mitre.org/data/definitions/1278.html)

**MITRE D3FEND**
  - [`D3-PSH`](https://d3fend.mitre.org/technique/D3-PSH/)

**Related rules**
  - [`SEC-IAM-001`](./SEC-IAM-001.md)

**Source**
  - [`catalog/STK-GCP-GKE-NODEPOOL-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-GKE-NODEPOOL-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-GKE-NODEPOOL-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-GKE-NODEPOOL-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-GKE-NODEPOOL-001
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
