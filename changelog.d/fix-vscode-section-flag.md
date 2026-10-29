## The VS Code `section` setting scans instead of failing

- **Extension**: with `tf-analyze.section` set, the extension passed
  `--section <s>` to the engine for the scan and the report panel. The
  engine has no `--section` flag (it is `--focus`), so it stopped with a
  usage error (exit 2) and nothing was scanned. Both now pass `--focus`.
  A new test reads every `--flag` the extension's source passes and
  checks the engine accepts it.
- **Engine**: `--focus <section>` now narrows a scan to that catalogue
  section, as its help text said. It only filtered `--list-rules` before,
  so `--focus security` on a scan still reported every section. A section
  with no rules (`--focus secuirty`) exits 2 instead of passing with no
  findings.
