FROM python:3.12-slim AS base

WORKDIR /tf-analyze

# git is required by the GitHub Action's diff mode (shells out to
# `git diff --name-only` to scope analysis to changed files). Without it,
# mode: auto on PR events crashes with FileNotFoundError: 'git'.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

# R31.7 — copy every Python module in scripts/, not just detect.py.
# The R30.13 → R30.15 refactor split detect.py into 24 sibling modules
# (`_apply_fixes.py`, `_attack_graph.py`, `_handlers_*.py`, …); the
# Dockerfile kept the pre-refactor single-file COPY and silently broke.
# Result: 20+ consecutive docker build failures with `ModuleNotFoundError:
# No module named '_versions'` at the smoke-test step, and no published
# image since 2026-05-11. Globbing fixes this both retroactively and for
# any future siblings.
COPY scripts/*.py ./
# The engine's HCL parser (python-hcl2 + lark) is vendored in
# scripts/_vendor/; copy it with the modules and pre-build its grammar
# cache so each run doesn't rebuild it (~0.35s).
COPY scripts/_vendor/ ./_vendor/
RUN python3 vendor_deps.py --warm-cache
COPY catalog/ ./catalog/

RUN python3 detect.py --list-rules --catalog ./catalog/ > /dev/null

RUN useradd -r -u 1001 tfanalyze
USER tfanalyze

ENTRYPOINT ["python3", "/tf-analyze/detect.py", "--catalog", "/tf-analyze/catalog/"]
