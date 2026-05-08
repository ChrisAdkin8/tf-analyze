FROM python:3.12-slim AS base

WORKDIR /tf-analyze

COPY scripts/detect.py .
COPY catalog/ ./catalog/

RUN python3 detect.py --list-rules --catalog ./catalog/ > /dev/null

RUN useradd -r -u 1001 tfanalyze
USER tfanalyze

ENTRYPOINT ["python3", "/tf-analyze/detect.py", "--catalog", "/tf-analyze/catalog/"]
