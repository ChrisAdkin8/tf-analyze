# Auto-generated clean fixture for ROB-GCP-DISK-SNAP-001.
# GCP Compute disk missing snapshot schedule
# This is a CORRECT configuration; ROB-GCP-DISK-SNAP-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_disk" "example" {
  name              = "data"
  type              = "pd-ssd"
  size              = 100
  zone              = "us-central1-a"
  resource_policies = [google_compute_resource_policy.daily.id]
}
