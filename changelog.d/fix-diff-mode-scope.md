## `--mode diff` scans what a change can affect

- **Variables and `.tfvars`**: diff mode re-scanned only the `.tf` files
  the PR changed. A PR that only flipped `variable "public" { default =
  true }` in `variables.tf`, or a value in `terraform.tfvars`, never
  re-checked `main.tf` where `publicly_accessible = var.public` lives,
  and the gate passed. A changed `.tfvars`, a changed file that declares
  `variable` or `locals`, or a deleted or moved file now re-scans every
  `.tf` file in its folder (one Terraform module), and every local module
  (`source = "./modules/db"`) those files call, since the caller passes
  values in. A change to resources only still scans just that file (and
  the local modules it calls).
- **Untracked files under a subfolder target**: with `--target infra/`,
  a new, not-yet-added `infra/new.tf` was looked up at the repo root,
  wasn't found, and was dropped without a warning. It is now scanned.
