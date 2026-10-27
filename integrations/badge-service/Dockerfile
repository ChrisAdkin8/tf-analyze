FROM python:3.12-slim

WORKDIR /app

COPY integrations/badge-service/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY integrations/badge-service/server.py /app/server.py

# TFA_BADGE_INGEST_SECRET must be set at runtime; without it /ingest
# returns 503 (refusing unauthenticated writes).
# Run as an unprivileged user, like the root Dockerfile: the service
# handles untrusted input (webhooks / tool calls / uploads).
RUN useradd -r -u 1001 tfanalyze
USER tfanalyze

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
