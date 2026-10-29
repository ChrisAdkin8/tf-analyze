## `--mode verify-fixed` doesn't call an unfixed finding resolved

- **Re-probe context**: verify-fixed re-ran each rule on the file without
  the folder's variable values or the module's other resources. A finding
  that depends on them (`publicly_accessible = var.public` with
  `default = true`) could never fire again, so on an unchanged tree it
  came out RESOLVED and the `--fail-on` gate passed. Verify-fixed now
  re-probes through the same per-file scanner as a full scan.
