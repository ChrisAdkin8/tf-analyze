FROM python:3.12-slim

WORKDIR /app

COPY integrations/mcp-server/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Bundle the engine alongside the server so the container is self-
# contained — the same pattern used by the bundled-engine VS Code
# extension and the run-task / badge-service deploys.
#
# Copy every engine module, not just detect.py: detect.py imports its
# `_*.py` siblings, so a detect.py-only COPY builds fine but crashes on the
# first scan (the same regression the root Dockerfile hit in R31.7).
COPY scripts/*.py /tf-analyze/scripts/
# The engine's HCL parser (python-hcl2 + lark) is vendored in
# scripts/_vendor/; copy it with the modules and pre-build its grammar
# cache so each run doesn't rebuild it (~0.35s).
COPY scripts/_vendor/ /tf-analyze/scripts/_vendor/
RUN python3 /tf-analyze/scripts/vendor_deps.py --warm-cache
COPY catalog/ /tf-analyze/catalog/
COPY integrations/mcp-server/server.py /app/server.py

# Build-time smoke tests: fail the build if the bundled engine can't load
# or the server can't import (an unpinned `mcp` once built an image whose
# server crashed on start, and only the engine was checked).
RUN python3 /tf-analyze/scripts/detect.py --list-rules > /dev/null
RUN TFA_REPO_ROOT=/tf-analyze python3 -c "import sys; sys.path.insert(0, '/app'); import server"

ENV TFA_REPO_ROOT=/tf-analyze
ENV TFA_DETECT_PY=/tf-analyze/scripts/detect.py

# Default transport is stdio — suitable for `claude_desktop_config.json`
# style spawning. For network deployment, swap CMD to a streamable-HTTP
# transport (operator decision; not the default).
# Run as an unprivileged user, like the root Dockerfile: the service
# handles untrusted input (webhooks / tool calls / uploads).
RUN useradd -r -u 1001 tfanalyze
USER tfanalyze

CMD ["python3", "/app/server.py"]
