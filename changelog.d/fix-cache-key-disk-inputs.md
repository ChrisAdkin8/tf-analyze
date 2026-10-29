## `--cache` notices a new state file, and `SEC-STATE-001` checks every folder

- **Stale cache**: two corpus checks find files by walking the disk
  rather than reading scanned text: `SEC-STATE-001` (a committed
  `*.tfstate*`) and `CI-TEST-001` (a module with no `*.tftest.hcl`). The
  `--cache` key didn't cover those files, so after a `terraform.tfstate`
  was committed, a warm cache was a hit and the CRITICAL finding was
  missing until an unrelated `.tf` change. Their paths are now part of the
  key. The cache format is bumped to 3, so existing caches are rebuilt once.
- **Missed state files**: `SEC-STATE-001` walked only the folder of the
  first scanned `.tf` file. When the target itself had no `.tf` files,
  a state file in another module folder (`b/` when `a/main.tf` came
  first) was never reported. The walk now starts at the target and
  skips `ignore_paths`.
