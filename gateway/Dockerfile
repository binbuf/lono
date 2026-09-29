FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src

RUN pip install ".[minio]"

RUN useradd --create-home --uid 1000 lono && mkdir -p /data && chown -R lono:lono /data
USER lono

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8080/healthz')"

CMD ["python", "-m", "lono_gateway"]