FROM python:3.12-slim

WORKDIR /app

COPY integrations/run-task/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt python-hcl2==4.3.5


# Copy every engine module, not just detect.py: detect.py imports its
# `_*.py` siblings, so a detect.py-only COPY builds fine but crashes on the
# first scan (the same regression the root Dockerfile hit in R31.7).
COPY scripts/*.py /tf-analyze/scripts/
COPY catalog/ /tf-analyze/catalog/
COPY integrations/run-task/server.py /app/server.py

# Build-time smoke tests: fail the build if the bundled engine can't load,
# or if the server can't import (it resolves the engine via TFA_REPO_ROOT).
RUN python3 /tf-analyze/scripts/detect.py --list-rules > /dev/null
RUN TFA_REPO_ROOT=/tf-analyze python3 -c "import sys; sys.path.insert(0, '/app'); import server; assert server.DETECT_PY.exists(), server.DETECT_PY"

ENV TFA_REPO_ROOT=/tf-analyze
ENV TFA_RUN_TASK_FAIL_ON=HIGH
ENV TF_ANALYZE_NO_HCL2=0

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
