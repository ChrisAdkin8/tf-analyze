# pre-commit hooks index PR

The [pre-commit.com](https://pre-commit.com) site has a curated index
of community hooks at https://pre-commit.com/hooks.html. Listing
there gets us search SEO and discoverability through `pre-commit`'s
own ecosystem.

The repo to PR against is
[`pre-commit/pre-commit.com`](https://github.com/pre-commit/pre-commit.com),
file `all-hooks.json`. Each entry is a {name, repo, hooks: [...]}
record. They generate the rendered table from the JSON.

## Prerequisites

The repo must already have a top-level `.pre-commit-hooks.yaml` (we
do — it ships three hook variants: `tf-analyze`, `tf-analyze-security`,
`tf-analyze-critical`).

The PR title format the maintainers prefer:

> Add hooks: ChrisAdkin8/tf-analyze

## PR description

```markdown
Adds [`tf-analyze`](https://github.com/ChrisAdkin8/tf-analyze) — a
Terraform security and stack analyser — to the pre-commit hooks
index.

The hook runs `python3 scripts/detect.py` against staged `.tf` files
and fails the commit on findings at or above a configurable urgency
threshold. Three variants are exposed:

- `tf-analyze` — fail on HIGH or above (default)
- `tf-analyze-security` — security section only, fail on HIGH+
- `tf-analyze-critical` — fail only on CRITICAL findings

The implementation is stdlib-only Python (no `pip install` step),
optional `python-hcl2` fast-path. 209 rules across AWS / GCP / Azure
/ Kubernetes / Helm, all with an `fix_hcl` remediation snippet.

[`.pre-commit-hooks.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/.pre-commit-hooks.yaml)
defines the three entry points; the rendered hook docs live at
[`docs/pre-commit.md`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/docs/pre-commit.md).

I've tagged `v0.1.0` for the initial public release; users would
pin via `rev: v0.1.0` in their `.pre-commit-config.yaml`.

Happy to address any review notes on the hook stanzas.
```

## After it merges

Add a "as a pre-commit hook" badge to the README:

```markdown
[![pre-commit](https://img.shields.io/badge/pre--commit-listed-brightgreen?logo=pre-commit)](https://pre-commit.com/hooks.html)
```

(Already wired in the README badges row — just needs the index
listing to make the link land in the right place.)
