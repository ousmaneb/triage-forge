FROM python:3.12-slim AS build
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install ".[otel]"

FROM python:3.12-slim
WORKDIR /app
RUN useradd --create-home --uid 10001 app
COPY --from=build /install /usr/local
COPY src ./src
COPY data ./data
# Models are trained at build time so containers start fast and every image carries the exact
# model version its evaluation ran against.
RUN TF_MODEL_DIR=/app/models python -m triage_forge.cli train && chown -R app /app
USER app
ENV TF_DATA_DIR=/app/data TF_MODEL_DIR=/app/models TF_AUDIT_LOG=/app/audit/audit.jsonl PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"
CMD ["uvicorn", "triage_forge.main:app", "--host", "0.0.0.0", "--port", "8080"]
