FROM python:3.12-slim

WORKDIR /app

COPY integrations/run-task/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt python-hcl2==4.3.5

COPY scripts/detect.py /tf-analyze/scripts/detect.py
COPY catalog/ /tf-analyze/catalog/
COPY integrations/run-task/server.py /app/server.py

ENV TFA_RUN_TASK_FAIL_ON=HIGH
ENV TF_ANALYZE_NO_HCL2=0

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
