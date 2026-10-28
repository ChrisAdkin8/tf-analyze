## Changelog entries no longer conflict

- **Fragments**: a PR now adds its entry as `changelog.d/<branch-name>.md`
  instead of editing `CHANGELOG.md`. Every PR used to add its section at
  the same place, so any two open PRs conflicted, and PRs open at once
  claimed the same round number (#99, #100 and #101 all claimed Round 86).
- **`scripts/changelog.py build`** numbers the rounds in the order the
  fragments reached `main`, adds the date, and moves them into
  `CHANGELOG.md`.
- **CI**: the new `changelog fragment present` check fails a PR that adds
  no fragment or edits `CHANGELOG.md` directly; the `no-changelog` label
  skips it. The release workflow refuses to tag while fragments are unbuilt.
