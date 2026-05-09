# ⚠️ SEC-GCP-LOGGING-001 — Cloud Audit Logs not configured

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **Cloud Audit Logs not configured.** This rule has `default_urgency: HIGH` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`resource_absent`** on `google_project_iam_audit_config` — _the corpus is missing a resource type we expected to find given other resources present._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-LOGGING-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `google_project_iam_audit_config` resources covering at minimum
`aiplatform.googleapis.com`, `storage.googleapis.com`, `iam.googleapis.com`,
and any service that processes regulated data. Enable ADMIN_READ,
DATA_READ, and DATA_WRITE log types.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_project_iam_audit_config" "all_services" {
  project = var.project_id
  service = "allServices"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}
```

## Verification

Run `gcloud logging read 'logName="projects/<project>/logs/cloudaudit.googleapis.com%2Fdata_access"' --limit 1`
and confirm at least one event is returned.

## References

**CIS Benchmark**
  - `CIS 2.1`

**PCI-DSS**
  - `Req-10.2`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1562.008`](https://attack.mitre.org/techniques/T1562/008/)

**Source**
  - [`catalog/SEC-GCP-LOGGING-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-LOGGING-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-LOGGING-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-LOGGING-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-LOGGING-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
