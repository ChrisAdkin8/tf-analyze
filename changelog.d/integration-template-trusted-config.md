## The workflow template reads config from the base branch too

- **`integrations/github-action.yml`**: the copy-paste workflow scanned the
  PR's own checkout, so a PR could add `ignore_rules`, a
  `.tf-analyze-ignore.yaml` or an emptied `rules_dir` and switch off the scan
  that checks it (Round 71 fixed this for `action.yml` only). On
  `pull_request` a new step replaces `.tf-analyze.yaml`,
  `.tf-analyze-ignore.yaml` and the config's `rules_dir` with the base
  branch's copies before the scan. It edits the checkout instead of passing
  flags, so it works with older engine releases picked by `ref`. A
  `rules_dir` that is absolute or climbs out with `..` is left alone.
- **Symlinks and base changes**: a symlink anywhere on the `rules_dir` path
  in the PR's checkout stops the job instead of letting the swap delete or
  write outside it. The template's `pull_request` trigger adds `edited`, so
  switching a PR's base branch re-runs the scan against the new base's
  config; the README suggests the same for `action.yml` workflows.
- **Inline suggestion comments** escape the rule title and size the
  suggestion fence to the fix, like the Action (Rounds 72 and 80).
