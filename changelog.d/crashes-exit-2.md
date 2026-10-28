## A crash is an error, not a findings result

- **Exit 2 on a crash**: Python exits 1 on an uncaught exception, which is
  the "findings found" code, so every crash passed for a scan result.
  `detect.main` now prints the traceback and exits 2. Deliberate exits are
  unchanged, and Ctrl-C exits 130.
- **Plan / state JSON**: a resource that isn't an object, a non-object
  `values` or a non-list `child_modules` raised `AttributeError` in the
  walker. Malformed entries are now skipped.
- **Language server**: a frame with bad JSON, a JSON array or a header
  without `Content-Length` raised outside the handler's `try`, which ended
  the server (VS Code stops restarting it after five crashes). It now
  answers with JSON-RPC `-32700` / `-32600` and keeps reading.
