FROM python:3.12-slim

WORKDIR /app

COPY integrations/mcp-server/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt python-hcl2==4.3.5

# Bundle the engine alongside the server so the container is self-
# contained — the same pattern used by the bundled-engine VS Code
# extension and the run-task / badge-service deploys.
COPY scripts/detect.py /tf-analyze/scripts/detect.py
COPY catalog/ /tf-analyze/catalog/
COPY integrations/mcp-server/server.py /app/server.py

ENV TFA_REPO_ROOT=/tf-analyze
ENV TFA_DETECT_PY=/tf-analyze/scripts/detect.py

# Default transport is stdio — suitable for `claude_desktop_config.json`
# style spawning. For network deployment, swap CMD to a streamable-HTTP
# transport (operator decision; not the default).
CMD ["python3", "/app/server.py"]
