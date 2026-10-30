## Diff mode sees changed `.tfvars` and non-ASCII paths, and scans used modules in `.terraform/`

- **Changed `.tfvars` in `--mode diff`**: the rules that read non-Terraform
  files (`.tfvars`, `.github/workflows/*.yml`) only ran in a full scan. A
  secret added to `prod.auto.tfvars` was a CRITICAL in a full scan and
  passed the diff gate. Diff mode now scans every changed file these rules
  read; unchanged ones still add nothing.
- **Non-ASCII paths in `--mode diff`**: git printed `café/main.tf` as
  `"caf\303\251/main.tf"`, which names no file, so the file was dropped
  without a warning and the gate passed. Path-listing git calls now use
  `core.quotepath=off` and NUL-separated output, so names with non-ASCII
  bytes, quotes or newlines survive. Trend mode's file list and
  `changelog.py check` had the same fault and are fixed too.
- **Modules under `.terraform/`**: nothing there was scanned, even a
  module real Terraform loads through `source = "./.terraform/m"`. An
  insecure module could hide there and exit 0. `.terraform/` is still
  skipped by default, but a file a local `source` reaches from a scanned
  file is now scanned, in every mode, directly or through other modules.
  The search stays inside the target (and folders linked into it), honours
  `ignore_paths`, and can't loop. `--target` pointing inside a `.terraform`
  folder now scans it, where it used to find no files.
- **Symlink loop as a module `source`**: this crashed the scan on
  Python 3.12 and older (exit 2). The source is now skipped.
