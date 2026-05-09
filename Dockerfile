FROM python:3.12-slim AS base

WORKDIR /tf-analyze

# git is required by the GitHub Action's diff mode (shells out to
# `git diff --name-only` to scope analysis to changed files). Without it,
# mode: auto on PR events crashes with FileNotFoundError: 'git'.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

# python-hcl2 is the heredoc-aware fast-path; bundling it removes a class
# of false positives around multi-line attributes. detect.py still works
# without it (regex fallback) — this is a quality upgrade, not a hard dep.
RUN pip install --no-cache-dir python-hcl2==4.3.5

COPY scripts/detect.py .
COPY catalog/ ./catalog/

RUN python3 detect.py --list-rules --catalog ./catalog/ > /dev/null

RUN useradd -r -u 1001 tfanalyze
USER tfanalyze

ENTRYPOINT ["python3", "/tf-analyze/detect.py", "--catalog", "/tf-analyze/catalog/"]
