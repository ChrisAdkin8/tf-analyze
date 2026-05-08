FROM python:3.12-slim
WORKDIR /app

COPY demo/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY scripts/detect.py scripts/detect.py
COPY catalog/ catalog/
COPY demo/app.py app.py
COPY demo/index.html index.html

RUN useradd -r -u 1001 demouser
USER demouser

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
