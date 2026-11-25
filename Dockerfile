# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY safeexec ./safeexec
RUN pip install --no-cache-dir --upgrade pip build \
    && python -m build --wheel --outdir /dist

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl \
    && rm -f /tmp/*.whl \
    && useradd --create-home --uid 10001 safeexec
COPY --chown=safeexec:safeexec safeexec/rules.yaml /app/rules.yaml
USER safeexec
ENV SAFEEXEC_RULES=/app/rules.yaml \
    PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status == 200 else 1)"
ENTRYPOINT ["safe-exec-service"]
