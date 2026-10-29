## Files, rules and findings a scan silently left out

- **Non-UTF-8 files**: one byte that isn't UTF-8 (a Latin-1 `é` in a
  comment) made the whole file unreadable, so every finding in it was
  lost. Files are now read as UTF-8 on every platform (Windows used the
  locale's codec and could break valid UTF-8 too), a byte-order mark is
  dropped, and a bad byte is replaced: the file is scanned, line numbers
  hold, and a `WARN` names it. Plan / state JSON, baselines, ignore files
  and config are read as UTF-8 too.
- **Commented-out version pins**: a `# azurerm = { version = "~> 2.99" }`
  or a `/* terraform { ... } */` block was read as the real pin and
  switched `applies_when` rules off. Comments and heredocs are skipped.
- **Version pins are per module**: every folder's `required_providers`
  were merged into one pin for the whole tree, so a `modules/legacy`
  pinning an old provider switched rules off for the root module too.
  Each folder is now gated by its own pin combined with the pins of the
  modules that call it (a child runs under its caller's providers); with
  several callers, a rule is skipped only if every caller rules it out.
  A folder no one calls and with no pin uses its nearest pinned parent
  folder's pin, else it is not gated. stderr reports rules skipped
  everywhere and rules skipped in some folders.
- **Symlinked module folders**: a module linked in as `net -> ../shared`
  was never scanned. Symlinked folders are now followed (each real
  folder once, loop-safe). One that leaves the target is followed only
  inside the same git repository, never in fleet mode, and never to a
  parent of the target; a link not followed gets a `WARN`.
- **`--mode diff` and module callers**: a change to a local child module
  (say an output) now also re-scans the folders that call it.
- **Inline ignore scope**: a trailing `key = "x" # tf-analyze:ignore ID`
  also suppressed the next line. Only a comment on a line by itself
  covers the next line now. `// tf-analyze:ignore ID` works too.
