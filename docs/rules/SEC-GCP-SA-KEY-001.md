# ⚠️ SEC-GCP-SA-KEY-001 — GCP service account key created in Terraform

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **GCP service account key created in Terraform.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_present`** on `google_service_account_key` — _this resource type exists in the corpus and is itself a finding._
  Any `google_service_account_key` resource. Creating a service account
key in Terraform bakes the base64-encoded private key into Terraform
state. The key is a long-lived credential with no automatic rotation
that persists in state (and therefore in any state-backend snapshot or
S3 version) even after the resource is destroyed unless state is
explicitly purged.

CIS GCP Foundations Benchmark v1.3 §1.4 states: "service account keys
should not be created for user-managed service accounts." The preferred
patterns are Workload Identity (for GKE workloads), Workload Identity
Federation (for CI systems), or short-lived tokens via
`google_service_account_access_token`.

## Why it likely fired

Any `google_service_account_key` resource. Creating a service account
key in Terraform bakes the base64-encoded private key into Terraform
state. The key is a long-lived credential with no automatic rotation
that persists in state (and therefore in any state-backend snapshot or
S3 version) even after the resource is destroyed unless state is
explicitly purged.

CIS GCP Foundations Benchmark v1.3 §1.4 states: "service account keys
should not be created for user-managed service accounts." The preferred
patterns are Workload Identity (for GKE workloads), Workload Identity
Federation (for CI systems), or short-lived tokens via
`google_service_account_access_token`.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-SA-KEY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove the `google_service_account_key` resource and migrate to one of:

1. **GKE workloads** — Workload Identity:
   ```hcl
   resource "google_service_account_iam_member" "wi" {
     service_account_id = google_service_account.app.name
     role               = "roles/iam.workloadIdentityUser"
     member             = "serviceAccount:${var.project}.svc.id.goog[${var.namespace}/${var.ksa}]"
   }
   ```
   Set `google_container_cluster.workload_identity_config.workload_pool`.

2. **CI/CD pipelines** — Workload Identity Federation:
   ```hcl
   resource "google_iam_workload_identity_pool" "ci" { … }
   resource "google_iam_workload_identity_pool_provider" "github" { … }
   ```
   No key file; pipeline asserts its OIDC token to get a short-lived token.

3. **Short-lived tokens** (rare on-premise need):
   Use `google_service_account_access_token` data source for ephemeral
   tokens scoped to a single call rather than a persistent key.

If you must keep a key temporarily, encrypt the output with Cloud KMS
before writing to any storage and rotate at least every 90 days.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Replace service account key with Workload Identity (GKE example)
resource "google_service_account_iam_member" "wi" {
  service_account_id = google_service_account.app.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project}.svc.id.goog[${var.namespace}/${var.ksa}]"
}

resource "google_container_cluster" "app" {
  workload_identity_config {
    workload_pool = "${var.project}.svc.id.goog"
  }
}
# Remove the google_service_account_key resource entirely
```

## Verification

```sh
`gcloud iam service-accounts keys list --iam-account <SA_EMAIL>` should
return only system-managed keys (type = SYSTEM_MANAGED). Re-run tf-analyze
— SEC-GCP-SA-KEY-001 must not fire.
```

## References

**CIS Benchmark**
  - `CIS 1.4`

**Source**
  - [`catalog/SEC-GCP-SA-KEY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-SA-KEY-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-SA-KEY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-SA-KEY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-SA-KEY-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
