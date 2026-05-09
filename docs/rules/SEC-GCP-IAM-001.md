# ⚠️ SEC-GCP-IAM-001 — Project-level binding of overly broad role

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **Project-level binding of overly broad role.** This rule has `default_urgency: HIGH` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`resource_arg`** on `google_project_iam_member` (`role`) matching `/^roles/(owner|editor|admin|iam\\.securityAdmin|resourcemanager\\.organizationAdmin|resourcemanager\\.folderAdmin|resourcemanager\\.projectAdmin|compute\\.admin|storage\\.admin|container\\.admin|cloudsql\\.admin|bigquery\\.admin|pubsub\\.admin|secretmanager\\.admin|dataproc\\.admin|appengine\\.appAdmin)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
2. **`resource_arg`** on `google_project_iam_binding` (`role`) matching `/^roles/(owner|editor|admin|iam\\.securityAdmin|resourcemanager\\.organizationAdmin|resourcemanager\\.folderAdmin|resourcemanager\\.projectAdmin|compute\\.admin|storage\\.admin|container\\.admin|cloudsql\\.admin|bigquery\\.admin|pubsub\\.admin|secretmanager\\.admin|dataproc\\.admin|appengine\\.appAdmin)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-IAM-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace the broad role with a narrowly-scoped resource-level binding.
See Appendix A for the IAM compatibility matrix — not every service
exposes a `_iam_member` resource. Where resource-level binding is not
possible (Cloud Workflows, Cloud Build, Document AI, Vertex AI, Cloud
SQL), apply IAM Conditions on the project-level binding instead.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_project_iam_member" "example" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.example.email}"
}
```

## Verification

Run `terraform plan` and confirm the broad project-level binding is
destroyed and the narrow binding is created. Re-run `tf-analyze` in
mode:verify-fixed and confirm SEC-IAM-001 is RESOLVED.

## References

**CIS Benchmark**
  - `CIS 1.6`

**PCI-DSS**
  - `Req-7.1`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**Source**
  - [`catalog/SEC-GCP-IAM-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-IAM-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-IAM-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-IAM-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-IAM-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
