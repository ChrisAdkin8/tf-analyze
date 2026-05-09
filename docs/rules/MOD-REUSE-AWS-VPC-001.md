---
title: "MOD-REUSE-AWS-VPC-001 — Hand-rolled VPC scaffolding could be replaced by terraform-aws-modules/vpc/aws"
description: "tf-analyze rule MOD-REUSE-AWS-VPC-001 (INFO · module-reuse): Hand-rolled VPC scaffolding could be replaced by terraform-aws-modules/vpc/aws"
keywords: "module-reuse, info, terraform, iac, aws"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "MOD-REUSE-AWS-VPC-001 \u2014 Hand-rolled VPC scaffolding could be replaced by terraform-aws-modules/vpc/aws",
  "description": "Consider replacing this hand-rolled VPC stack with the community module:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-REUSE-AWS-VPC-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-REUSE-AWS-VPC-001/"
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

# · MOD-REUSE-AWS-VPC-001 — Hand-rolled VPC scaffolding could be replaced by terraform-aws-modules/vpc/aws

![INFO](https://img.shields.io/badge/INFO-3498db?style=flat-square) ![Section: module-reuse](https://img.shields.io/badge/section-module-reuse-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/MOD-REUSE-AWS-VPC-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=MOD-REUSE-AWS-VPC-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add MOD-REUSE-AWS-VPC-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Hand-rolled VPC scaffolding could be replaced by terraform-aws-modules/vpc/aws.** This rule has `default_urgency: INFO` and operates on a module blast radius. 

## What this checks

1. **`registry_fingerprint`** — _a `registry_fingerprint` pattern._
  Resource cluster in this directory matches the shape of the
terraform-aws-modules/vpc/aws community module: a VPC plus subnets
and the usual gateway/routing scaffolding. The community module
has been battle-tested across thousands of installations and
tracks AWS feature deltas (NAT-gateway HA, IPv6, flow logs,
VPC endpoints) so consumers don't have to.

## Why it likely fired

Resource cluster in this directory matches the shape of the
terraform-aws-modules/vpc/aws community module: a VPC plus subnets
and the usual gateway/routing scaffolding. The community module
has been battle-tested across thousands of installations and
tracks AWS feature deltas (NAT-gateway HA, IPv6, flow logs,
VPC endpoints) so consumers don't have to.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain MOD-REUSE-AWS-VPC-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Consider replacing this hand-rolled VPC stack with the community module:

    module "vpc" {
      source  = "terraform-aws-modules/vpc/aws"
      version = "~> 5.0"

      name = "my-vpc"
      cidr = "10.0.0.0/16"

      azs             = ["us-east-1a", "us-east-1b"]
      private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
      public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]

      enable_nat_gateway     = true
      single_nat_gateway     = false
      one_nat_gateway_per_az = true

      tags = local.tags
    }

This is informational — bespoke VPCs are sometimes deliberate
(compliance, IPAM, custom routing). Suppress with an inline
`# tf-analyze:disable=MOD-REUSE-AWS-VPC-001` comment if intentional,
or list the rule under `ignore_rules:` in `.tf-analyze.yaml`.

## Verification

After migrating, run `terraform plan` to confirm the topology is
equivalent. Use `moved` blocks to map old `aws_vpc.<x>` /
`aws_subnet.<y>` addresses to their new `module.vpc.aws_vpc.this[0]`
counterparts so no real network is destroyed and recreated.

## References

**Related rules**
  - [`MOD-PIN-001`](./MOD-PIN-001.md)
  - [`MOD-SUPPLY-001`](./MOD-SUPPLY-001.md)

**Source**
  - [`catalog/MOD-REUSE-AWS-VPC-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/MOD-REUSE-AWS-VPC-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain MOD-REUSE-AWS-VPC-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore MOD-REUSE-AWS-VPC-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - MOD-REUSE-AWS-VPC-001
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
