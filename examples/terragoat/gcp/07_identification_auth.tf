# OWASP A07:2021 — Identification and Authentication Failures
# Cloud: GCP
#
# In GCP Terraform, the most consequential auth failures are at the
# pod-to-cloud boundary. Two anti-patterns:
#
#   1. GKE clusters without `workload_identity_config`. Pods that
#      need GCP access must mount a service-account JSON key as a
#      Kubernetes Secret — a long-lived credential that survives
#      every pod restart, is hard to rotate, and ships in every
#      etcd backup.
#   2. Node pools without `shielded_instance_config.enable_secure_boot`
#      and `enable_integrity_monitoring`. Without these, any code
#      running on the node can persist via the bootloader.
#
# These are different controls — WI is "who is the pod", shielded VMs
# is "is the node trustworthy" — and they're often missed together
# because the cluster default ships them off.
#
# Real-world impact:
#   - A leaked JSON key remains valid for ~90 days even after the pod
#     is deleted; rotation requires a deploy.
#   - Without secure boot, a kernel-level rootkit on a node persists
#     across cordons / drains and even node-pool surge upgrades.
#
# Expected tf-analyze findings:
#   - STK-GCP-GKE-002              HIGH   GKE cluster missing Workload Identity
#   - SEC-GCP-GKE-NETWORK-POLICY-001 HIGH GKE cluster missing network_policy enforcement
#   - STK-GCP-GKE-NODEPOOL-001     HIGH   Node pool missing shielded-instance hardening
#   - STK-GCP-GKE-004              HIGH   GKE cluster missing master authorized networks
#
# Fix summary: enable Workload Identity at cluster create time,
# enforce `enable_secure_boot` + `enable_integrity_monitoring` on
# every node pool, and set `network_policy { enabled = true }`.

resource "google_container_cluster" "demo" {
  name                     = "demo-cluster"
  location                 = "us-central1"
  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = true

  # workload_identity_config intentionally omitted
  # network_policy intentionally omitted
  # master_authorized_networks_config intentionally omitted — STK-GCP-GKE-004 fires.
}

resource "google_container_node_pool" "default" {
  name     = "default"
  cluster  = google_container_cluster.demo.name
  location = "us-central1"

  node_config {
    machine_type = "e2-medium"
    # No shielded_instance_config block — secure boot and integrity
    # monitoring are off.
  }
}
