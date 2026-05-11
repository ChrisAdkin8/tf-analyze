---
title: "SEC-GCP-NETWORK-004 — GCP firewall rule exposes database or cache port to 0.0.0.0/0"
description: "tf-analyze rule SEC-GCP-NETWORK-004 (CRITICAL · security): GCP firewall rule exposes database or cache port to 0.0.0.0/0"
keywords: "security, critical, terraform, iac, gcp, cis-3.6, mitre-T1190, cwe-284, cwe-1327, d3-iaa, nist-csf-pr.ac-3, nist-800-53-sc-7, csa-ccm-ivs-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-NETWORK-004 \u2014 GCP firewall rule exposes database or cache port to 0.0.0.0/0",
  "description": "Remove the `allow` block for database/cache ports or restrict\n`source_ranges` to specific internal CIDR ranges:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-NETWORK-004/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-NETWORK-004/"
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
  "keywords": "security, critical, terraform, CIS 3.6, MITRE T1190, CWE-284, CWE-1327, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-GCP-NETWORK-004 — GCP firewall rule exposes database or cache port to 0.0.0.0/0

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-NETWORK-004" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-NETWORK-004" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-NETWORK-004 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP firewall rule exposes database or cache port to 0.0.0.0/0.** This rule has `default_urgency: CRITICAL` and operates on a environment blast radius. 

## What this checks

1. **`firewall_open_port`** — _a `google_compute_firewall` allows the named port from `0.0.0.0/0`._
  `google_compute_firewall` with `source_ranges = ["0.0.0.0/0"]` and an
`allow {}` block containing a database or cache port:
- 3306  MySQL / MariaDB
- 5432  PostgreSQL
- 1433  Microsoft SQL Server
- 5439  Amazon Redshift (also used on GCP for Redshift-compatible)
- 6379  Redis
- 11211 Memcached
- 27017 MongoDB primary
- 27018 MongoDB shard
- 9200  Elasticsearch / OpenSearch HTTP
- 9300  Elasticsearch / OpenSearch transport

These services were designed for private network use. Publicly exposed
database ports are routinely scanned and exploited within hours — the
MongoDB ransomware waves of 2017 and 2019 both required only a public
port and no authentication. Even with authentication, service-specific
CVEs (unauthenticated RCE in Redis, Elasticsearch default no-auth) make
exposure high-severity.

## Why it likely fired

`google_compute_firewall` with `source_ranges = ["0.0.0.0/0"]` and an
`allow {}` block containing a database or cache port:
- 3306  MySQL / MariaDB
- 5432  PostgreSQL
- 1433  Microsoft SQL Server
- 5439  Amazon Redshift (also used on GCP for Redshift-compatible)
- 6379  Redis
- 11211 Memcached
- 27017 MongoDB primary
- 27018 MongoDB shard
- 9200  Elasticsearch / OpenSearch HTTP
- 9300  Elasticsearch / OpenSearch transport

These services were designed for private network use. Publicly exposed
database ports are routinely scanned and exploited within hours — the
MongoDB ransomware waves of 2017 and 2019 both required only a public
port and no authentication. Even with authentication, service-specific
CVEs (unauthenticated RCE in Redis, Elasticsearch default no-auth) make
exposure high-severity.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-NETWORK-004` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove the `allow` block for database/cache ports or restrict
`source_ranges` to specific internal CIDR ranges:

```hcl
resource "google_compute_firewall" "db_internal" {
  name    = "allow-db-internal"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }

  # Only allow from the application subnet, never from 0.0.0.0/0
  source_ranges = [google_compute_subnetwork.app.ip_cidr_range]
}
```

For GKE workloads, use a Kubernetes `NetworkPolicy` (covered by
SEC-GCP-GKE-NETWORK-POLICY-001) instead of a VPC firewall rule.

For Cloud SQL, the correct pattern is the Cloud SQL Auth Proxy or
Private Service Access — not a public IP with firewall rules.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_compute_firewall" "db_internal" {
  name          = "allow-db-internal"
  network       = google_compute_network.vpc.id
  direction     = "INGRESS"
  source_ranges = [google_compute_subnetwork.app.ip_cidr_range]
  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }
  target_tags = ["db"]
}
```

## Verification

```sh
`gcloud compute firewall-rules list --filter="direction=INGRESS" \
  --format="table(name,allowed[].map().firewall_key():label=ALLOW,sourceRanges)"` —
confirm no row has `0.0.0.0/0` in source ranges and a database port in
the allow column. Re-run tf-analyze; SEC-GCP-NETWORK-004 must not fire.
```

## References

**CIS Benchmark**
  - `CIS 3.6`

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)
  - [`CWE-1327`](https://cwe.mitre.org/data/definitions/1327.html)

**MITRE D3FEND**
  - [`D3-IAA`](https://d3fend.mitre.org/technique/D3-IAA/)

**NIST CSF 2.0**
  - [`PR.AC-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-7)

**CSA CCM v4**
  - [`IVS-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-NETWORK-004.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-NETWORK-004.yaml) — canonical YAML

## Family

See also rules in the `SEC-GCP-NETWORK-*` family:

- [`SEC-GCP-NETWORK-001`](./SEC-GCP-NETWORK-001.md) — SSH (tcp:22) exposed to 0.0.0.0/0
- [`SEC-GCP-NETWORK-002`](./SEC-GCP-NETWORK-002.md) — RDP (tcp:3389) exposed to 0.0.0.0/0
- [`SEC-GCP-NETWORK-003`](./SEC-GCP-NETWORK-003.md) — VPC subnet missing flow logs

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-NETWORK-004    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-NETWORK-004` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-NETWORK-004
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
