FROM python:3.12-slim

# `git` is needed for the public scanner's shallow clone.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY demo/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Engine — ship every sibling Python file `detect.py` imports, not just
# `detect.py` itself. The list mirrors `vscode-extension/scripts/bundle-engine.js
# :ENGINE_SIBLING_FILES`. Adding a new helper module is a one-line update.
COPY scripts/detect.py scripts/detect.py
COPY scripts/_mitre.py scripts/_mitre.py
COPY scripts/_versions.py scripts/_versions.py
COPY scripts/_scoring.py scripts/_scoring.py
COPY scripts/_hcl.py scripts/_hcl.py
COPY scripts/_catalog.py scripts/_catalog.py
COPY scripts/_attack_graph.py scripts/_attack_graph.py
COPY scripts/_output.py scripts/_output.py
COPY scripts/_cross_resource.py scripts/_cross_resource.py
COPY scripts/_lsp.py scripts/_lsp.py
COPY scripts/_threat_intel.py scripts/_threat_intel.py
COPY scripts/_blast_radius.py scripts/_blast_radius.py
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
