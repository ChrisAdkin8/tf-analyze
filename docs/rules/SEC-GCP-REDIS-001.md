---
title: "SEC-GCP-REDIS-001 — Cloud Memorystore Redis instance AUTH disabled"
description: "tf-analyze rule SEC-GCP-REDIS-001 (HIGH · security): Cloud Memorystore Redis instance AUTH disabled"
keywords: "security, high, terraform, iac, gcp"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-REDIS-001 \u2014 Cloud Memorystore Redis instance AUTH disabled",
  "description": "Enable AUTH on the instance:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-REDIS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-REDIS-001/"
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
  "keywords": "security, high, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-GCP-REDIS-001 — Cloud Memorystore Redis instance AUTH disabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-REDIS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Cloud Memorystore Redis instance AUTH disabled.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_redis_instance` (`auth_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_redis_instance` has no `auth_enabled` argument. The default
is `false` — any client that can reach the Redis port can issue
commands (GET, SET, FLUSHALL, CONFIG) without a password.
2. **`resource_arg`** on `google_redis_instance` (`auth_enabled`) matching `/false/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `google_redis_instance` explicitly sets `auth_enabled = false`.
Password-free Redis access is permitted to any host on the VPC.

## Why it likely fired

`google_redis_instance` has no `auth_enabled` argument. The default
is `false` — any client that can reach the Redis port can issue
commands (GET, SET, FLUSHALL, CONFIG) without a password.

`google_redis_instance` explicitly sets `auth_enabled = false`.
Password-free Redis access is permitted to any host on the VPC.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-REDIS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable AUTH on the instance:

    resource "google_redis_instance" "cache" {
      name           = "cache"
      memory_size_gb = 1
      auth_enabled   = true
      transit_encryption_mode = "SERVER_AUTHENTICATION"
    }

AUTH is available on Redis 6.x and above (`redis_version = "REDIS_6_X"`
or higher). After `terraform apply`, retrieve the AUTH string via
`gcloud redis instances get-auth-string <name> --region=<region>` and
inject it into consuming workloads via Secret Manager — do not emit it
as a Terraform output.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_redis_instance" "example" {
  # ... other arguments ...
  auth_enabled = true
}
```

## Verification

```sh
`gcloud redis instances describe <name> --region=<region> \
  --format='value(authEnabled)'`
must return `True`.
```

## References

**Source**
  - [`catalog/SEC-GCP-REDIS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-REDIS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-REDIS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-REDIS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-REDIS-001
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
