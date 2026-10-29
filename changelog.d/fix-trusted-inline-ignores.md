## A pull request can't silence its own findings with an inline ignore

- **`--inline-ignores-from REF`** (new flag): an inline
  `# tf-analyze:ignore <ID>` is honoured only if the file at git `REF`
  has an ignore for the same rule on the same code. The match is by the
  code the comment covers (its own line for a trailing comment, else the
  next line of code), with whitespace normalised, not by line number, so
  lines added elsewhere in the file don't break it. It counts copies: if
  `REF` has the ignore on N identical lines, at most N are honoured. A
  file that `REF` doesn't have honours none. If `REF` can't be read (git
  missing, unknown ref, not a work tree, git refusing the repository),
  none are honoured, with one `WARN` and `inline_ignores_untrusted: true`
  in the JSON summary. Ignores not honoured are counted on stderr and
  listed in the summary as `inline_ignores_dropped`.
- **The GitHub Action passes it on PRs**: on `pull_request`,
  `pull_request_target` and `merge_group` runs (unless
  `trust-pr-config: true`) the composite action passes the base branch it
  already fetches for the trusted config. A PR adding
  `# tf-analyze:ignore SEC-AWS-SG-001` above the security group it opens
  used to pass `fail-on: CRITICAL`; the finding now shows. The action
  also warns when the base branch couldn't be read in the scan, notes how
  many inline ignores weren't honoured, drops a stale base ref left by an
  earlier run before fetching, and marks `/workspace` as a git
  `safe.directory` inside the container, so git works on runners whose
  checkout belongs to another user. The workflow template
  (`integrations/github-action.yml`) does the same on PRs when its engine
  `ref` has the flag, and warns when it doesn't.
- **Upgrade note**: on PRs, an inline ignore the PR adds no longer
  suppresses its finding until the PR is merged. Set
  `trust-pr-config: true` to honour the PR's own inline ignores as before.
- **Dogfood workflow**: the comment on its `mode: static` pin said the
  image lacks `git`; it has it. The pin stays because a diff scan of a
  PR that doesn't touch the demo would find nothing to check.
