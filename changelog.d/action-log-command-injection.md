## Engine output can't run workflow commands in the Actions log

- **`action.yml`**: the engine's stderr was printed to the log with `cat`.
  It names repo files, and a PR controls those names, so a directory name
  holding a newline could start a log line with `::error::`,
  `::add-mask::` or `::stop-commands::` and forge an annotation or hide
  the rest of the log. It is now printed between
  `::stop-commands::<token>` and `::<token>::`, with a random token per run.
- **`integrations/github-action-bot.yml`**: the same for the
  `--apply-fixes` output and the PR body it prints.
