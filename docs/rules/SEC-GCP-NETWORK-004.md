# 🚨 SEC-GCP-NETWORK-004 — GCP firewall rule exposes database or cache port to 0.0.0.0/0

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

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

**Source**
  - [`catalog/SEC-GCP-NETWORK-004.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-NETWORK-004.yaml) — canonical YAML

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

[← Index of all rules](./)
