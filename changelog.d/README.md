# Changelog fragments

Don't edit `CHANGELOG.md` in a PR. Add one file here instead, named after
your branch (e.g. `md-escape-ampersand.md`). Two PRs never touch the same
file, so they can't conflict over the changelog.

A fragment is a `##` heading with the title only, then the entry, written
the same way as the existing entries in `CHANGELOG.md`:

```markdown
## A character reference can't undo PR-comment escaping

- **`&` is escaped**: Markdown turns a character reference such as `&#64;`
  into the character it names, so ...
```

Leave out `Round N` and the date. `python3 scripts/changelog.py build`
adds both, numbering rounds in the order the fragments reached `main`,
then moves the entries into `CHANGELOG.md` and deletes the fragments.
Run it in its own PR (and always before tagging a release; the release
workflow refuses to run while fragments are unbuilt).

`python3 scripts/changelog.py check` validates fragments. CI also runs
`check --base` on every PR: the PR must add a fragment, or carry the
`no-changelog` label if users won't notice the change.
