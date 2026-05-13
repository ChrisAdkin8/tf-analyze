# Pre-commit hook

tf-analyze ships as a [pre-commit](https://pre-commit.com) hook so every
`git commit` on a Terraform repo is gated automatically.

## Quick start

1. **Install pre-commit** (once per machine):
   ```bash
   pip install pre-commit
   # or: brew install pre-commit
   ```

2. **Add `.pre-commit-config.yaml`** to your repo root (or append to an existing one):
   ```yaml
   repos:
     - repo: https://github.com/ChrisAdkin8/tf-analyze
       rev: v0.2.6                   # pin to a release tag; bump as new tags ship
       hooks:
         - id: tf-analyze          # all findings, fail on HIGH+
   ```

3. **Install the hooks** into your local git repo:
   ```bash
   pre-commit install
   ```

4. **Run manually** against all staged files:
   ```bash
   pre-commit run tf-analyze
   ```

## Available hook IDs

| Hook ID | Scope | Fail on |
|---------|-------|---------|
| `tf-analyze` | All sections | `HIGH` and above |
| `tf-analyze-security` | `security` section only | `HIGH` and above |
| `tf-analyze-critical` | All sections | `CRITICAL` only |

## Customising the threshold

Override `args` in your `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/ChrisAdkin8/tf-analyze
    rev: v0.2.6
    hooks:
      - id: tf-analyze
        args: ["--target", ".", "--fail-on", "MEDIUM"]
```

## Scoping to a section

```yaml
hooks:
  - id: tf-analyze
    args: ["--target", ".", "--fail-on", "HIGH", "--section", "security"]
```

## CI integration

Pre-commit can also run in CI (GitHub Actions, GitLab CI, etc.):
```yaml
# .github/workflows/pre-commit.yml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: "3.11"
- run: pip install pre-commit
- run: pre-commit run tf-analyze --all-files
```

Or use the dedicated GitHub Action from `integrations/github-action.yml`.

## How it works

The hook calls:
```
python3 scripts/detect.py --target . --fail-on HIGH
```
from the root of the repo. It exits non-zero when any finding meets or
exceeds the threshold, blocking the commit.

`pass_filenames: false` is set because tf-analyze always scans the
workspace root (it resolves module boundaries across the corpus).
