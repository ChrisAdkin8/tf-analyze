---
title: "STK-AWS-LAUNCH-TEMPLATE-001 — EC2 launch template does not enforce IMDSv2"
description: "tf-analyze rule STK-AWS-LAUNCH-TEMPLATE-001 (HIGH · stack): EC2 launch template does not enforce IMDSv2"
keywords: "stack, high, terraform, iac, aws, mitre-T1552.005, cwe-668, d3-ch"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AWS-LAUNCH-TEMPLATE-001 \u2014 EC2 launch template does not enforce IMDSv2",
  "description": "Enforce IMDSv2 on every launch template:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AWS-LAUNCH-TEMPLATE-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AWS-LAUNCH-TEMPLATE-001/"
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
  "keywords": "stack, high, terraform, MITRE T1552.005, CWE-668, D3-CH",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-AWS-LAUNCH-TEMPLATE-001 — EC2 launch template does not enforce IMDSv2

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AWS-LAUNCH-TEMPLATE-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AWS-LAUNCH-TEMPLATE-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AWS-LAUNCH-TEMPLATE-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **EC2 launch template does not enforce IMDSv2.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. _Conditional: only applies when `aws ≥ 3.0`._

## What this checks

1. **`resource_missing_arg`** on `aws_launch_template` (`metadata_options.http_tokens`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_launch_template` without `metadata_options { http_tokens = "required" }`.
Launch templates without IMDSv2 enforcement allow nodes (EC2 and EKS node
groups using this template) to call IMDSv1, which is exploitable via SSRF.
2. **`hcl_attr`** on `aws_launch_template` (`metadata_options.http_tokens`) not equal to `"required"` — _an attribute value differs from the expected literal._
  `aws_launch_template` with `metadata_options.http_tokens` set to something
other than `"required"` — IMDSv2 not enforced.

## Why it likely fired

`aws_launch_template` without `metadata_options { http_tokens = "required" }`.
Launch templates without IMDSv2 enforcement allow nodes (EC2 and EKS node
groups using this template) to call IMDSv1, which is exploitable via SSRF.

`aws_launch_template` with `metadata_options.http_tokens` set to something
other than `"required"` — IMDSv2 not enforced.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AWS-LAUNCH-TEMPLATE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enforce IMDSv2 on every launch template:

    resource "aws_launch_template" "app" {
      # ...
      metadata_options {
        http_endpoint               = "enabled"
        http_tokens                 = "required"
        http_put_response_hop_limit = 1
      }
    }

For EKS managed node groups, the launch template feeds into
`aws_eks_node_group.launch_template`. Nodes without IMDSv2 are
exploitable from any pod with SSRF capability — the pod can reach
169.254.169.254 and steal the node's IAM role credentials.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_launch_template" "example" {
  name = "example"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
}
```

## Verification

```sh
`aws ec2 describe-launch-template-versions --launch-template-id <id>` —
`MetadataOptions.HttpTokens` must be `required`. Re-run tf-analyze mode:verify-fixed.
```

## References

**MITRE ATT&CK**
  - [`T1552.005`](https://attack.mitre.org/techniques/T1552/005/)

**CWE**
  - [`CWE-668`](https://cwe.mitre.org/data/definitions/668.html)

**MITRE D3FEND**
  - [`D3-CH`](https://d3fend.mitre.org/technique/D3-CH/)

**Related rules**
  - [`SEC-AWS-SSRF-001`](./SEC-AWS-SSRF-001.md)
  - [`STK-AWS-EKS-001`](./STK-AWS-EKS-001.md)

**Source**
  - [`catalog/STK-AWS-LAUNCH-TEMPLATE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AWS-LAUNCH-TEMPLATE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AWS-LAUNCH-TEMPLATE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AWS-LAUNCH-TEMPLATE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AWS-LAUNCH-TEMPLATE-001
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
