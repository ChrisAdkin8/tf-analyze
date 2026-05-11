FROM python:3.12-slim

# `git` is needed for the public scanner's shallow clone.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY demo/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Engine — ship `detect.py` plus every `_*.py` sibling it imports by side
# effect (R30.15 detector topic modules, R30.19 modular seams, the older
# `_hcl` / `_mitre` / `_scoring` helpers). Using a glob instead of an
# explicit per-file list so the next handler/seam extract is bundled
# automatically — the VS Code extension's bundle-engine.js uses the same
# pattern (`scripts/_*.py`) and has not drifted; this one had, which is
# how `_verify` and a dozen other modules went missing from this image
# until the public scanner started 500'ing.
COPY scripts/detect.py scripts/detect.py
COPY scripts/_*.py scripts/
COPY catalog/ catalog/

# Web app — keep `demo/` layout so app.py's `Path(__file__).parent.parent`
# resolves to the same place that `scripts/` lives in (i.e. /app).
# Flattening these to /app/app.py would break the path resolution.
COPY demo/app.py demo/app.py
COPY demo/_badge.py demo/_badge.py
COPY demo/index.html demo/index.html

# Cache dir for per-SHA scan results — mounted as a Fly volume.
RUN mkdir -p /var/cache/tf-analyze && chown 1001:1001 /var/cache/tf-analyze

RUN useradd -r -u 1001 demouser
USER demouser

ENV TFA_SCAN_CACHE_DIR=/var/cache/tf-analyze

# Run from /app/demo so uvicorn imports `app:app` from the demo dir.
WORKDIR /app/demo
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
