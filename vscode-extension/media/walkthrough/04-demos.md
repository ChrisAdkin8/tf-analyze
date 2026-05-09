## Try the showcase demos

Two corpora exercise the deeper panels end-to-end with realistic-shaped Terraform — richer than single-rule fixtures, scoped tightly enough to read in 5 minutes.

### 📦 `examples/module-reuse-demo/`

Five hand-rolled VPC / network / AKS clusters that all match popular community modules on the Terraform Registry. Open the directory as a workspace and click **📦 Module Reuse** in the Activity Bar.

What you'll see:

- Three rule-grouped sections (one per fingerprint: AWS VPC / GCP network / Azure AKS)
- Two AWS rows (high confidence), one GCP row (medium), two Azure rows (one high, one low) — the corpus is tuned so the panel renders all three confidence-badge colours

Two negative cases (`aws/admin-net/` and `gcp/shared-vpc-host/`) prove the rule's conservatism: bare clusters and Shared-VPC-host topologies look similar but the rule deliberately doesn't fire on them.

### 🛤 `examples/attack-graph-demo/`

Multi-tier AWS app — public ALB → public EC2 → over-broad IAM role → S3 / Secrets Manager / RDS crown jewels. Open the directory as a workspace and click **🛤 Attack Graph**.

What you'll see:

- 19 nodes, 13 edges, 6 internet-reachable nodes, 3 crown jewels
- The synthetic INTERNET node and its edges to every public-facing resource
- The IAM-instance-profile → IAM-role pivot rendered explicitly
- 27 findings across the file split (`network.tf` / `compute.tf` / `iam.tf` / `data.tf`)

Both demos are deliberately non-deployable — they exist for the panel UI, not for `terraform apply`.
