---
title: "MOD-REUSE-GCP-NETWORK-001 — Hand-rolled VPC + subnets could be replaced by terraform-google-modules/network/google"
description: "tf-analyze rule MOD-REUSE-GCP-NETWORK-001 (INFO · module-reuse): Hand-rolled VPC + subnets could be replaced by terraform-google-modules/network/google"
keywords: "module-reuse, info, terraform, iac, gcp"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "MOD-REUSE-GCP-NETWORK-001 \u2014 Hand-rolled VPC + subnets could be replaced by terraform-google-modules/network/google",
  "description": "Consider replacing this hand-rolled network with the community module:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-REUSE-GCP-NETWORK-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-REUSE-GCP-NETWORK-001/"
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
  "keywords": "module-reuse, info, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "module-reuse",
  "isAccessibleForFree": true
}
</script>

# · MOD-REUSE-GCP-NETWORK-001 — Hand-rolled VPC + subnets could be replaced by terraform-google-modules/network/google

![INFO](https://img.shields.io/badge/INFO-3498db?style=flat-square) ![Section: module-reuse](https://img.shields.io/badge/section-module-reuse-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/MOD-REUSE-GCP-NETWORK-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=MOD-REUSE-GCP-NETWORK-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add MOD-REUSE-GCP-NETWORK-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Hand-rolled VPC + subnets could be replaced by terraform-google-modules/network/google.** This rule has `default_urgency: INFO` and operates on a module blast radius. 

## What this checks

1. **`registry_fingerprint`** — _a `registry_fingerprint` pattern._
  Resource cluster in this directory matches the shape of the
terraform-google-modules/network/google community module: a
google_compute_network plus subnetworks, and typically firewall
/ Cloud-Router / NAT scaffolding.

## Why it likely fired

Resource cluster in this directory matches the shape of the
terraform-google-modules/network/google community module: a
google_compute_network plus subnetworks, and typically firewall
/ Cloud-Router / NAT scaffolding.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain MOD-REUSE-GCP-NETWORK-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Consider replacing this hand-rolled network with the community module:

    module "vpc" {
      source  = "terraform-google-modules/network/google"
      version = "~> 9.0"

      project_id   = var.project_id
      network_name = "my-vpc"

      subnets = [
        {
          subnet_name   = "subnet-a"
          subnet_ip     = "10.10.10.0/24"
          subnet_region = "us-central1"
        },
      ]
    }

Bespoke networks are sometimes deliberate (Shared VPC, hierarchical
firewall policies, custom peering). Suppress with an inline
`# tf-analyze:disable=MOD-REUSE-GCP-NETWORK-001` comment if
intentional, or via `.tf-analyze.yaml` `ignore_rules`.

## Verification

After migrating, run `terraform plan`. Pair every direct resource
with a `moved` block pointing at the equivalent
`module.vpc.google_compute_network.network[0]` address so the plan
is a pure no-op rather than a destroy/create.

## References

**Related rules**
  - [`MOD-PIN-001`](./MOD-PIN-001.md)
  - [`MOD-SUPPLY-001`](./MOD-SUPPLY-001.md)

**Source**
  - [`catalog/MOD-REUSE-GCP-NETWORK-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/MOD-REUSE-GCP-NETWORK-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain MOD-REUSE-GCP-NETWORK-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore MOD-REUSE-GCP-NETWORK-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - MOD-REUSE-GCP-NETWORK-001
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
