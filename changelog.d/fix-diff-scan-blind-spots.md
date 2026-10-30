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
  module real Terraform loads through `source = "./.terraform/m"` or a
  committed `.terraform/modules/modules.json`. An insecure module could
  hide there and exit 0. `.terraform/` is still skipped by default, but in
  every mode two kinds of file there are now scanned: any `.tf` or
  `.tfvars` file git tracks (committed files aren't a cache), and, for
  untracked files, what a local `source` reaches from a scanned file,
  directly or through other modules. That search stays inside the target
  (and folders linked into it), honours `ignore_paths`, walks no ignored
  module and can't loop. A `source` it can't follow gets a WARN while a
  `.terraform` folder is present. `--target` pointing inside a `.terraform`
  folder now scans it, tfvars included, where it used to find no files.
- **`..` in a module `source`**: `./link/../m` was resolved through the
  link first. Terraform cleans `..` as text first, so a different folder
  was read. Module paths now follow Terraform.
- **Changes `--mode diff` can't narrow**: git names only the link when a
  folder symlink is repointed, and only the folder when a submodule moves,
  so the changed code went unscanned and the gate passed. A changed folder
  symlink or submodule, a module `source` that isn't a plain string, and a
  failed `git ls-files` now fall back to a full scan with a WARN.
- **Symlink loops**: as a module `source` or as a file in a pull request,
  one crashed the scan on Python 3.12 and older (exit 2). A loop in a
  module `source` is now skipped; a changed one falls back to a full scan.
