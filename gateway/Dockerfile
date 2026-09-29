# Build the console SPA (Vite + Svelte 5) and bundle it into the gateway image.
FROM node:22-slim AS ui-build
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
RUN npm run build

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
COPY --from=ui-build /src/lono_gateway/ui/dist ./src/lono_gateway/ui/dist

RUN pip install ".[minio]"

RUN useradd --create-home --uid 1000 lono && mkdir -p /data && chown -R lono:lono /data
USER lono

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8080/healthz')"

CMD ["python", "-m", "lono_gateway"]