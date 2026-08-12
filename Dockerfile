FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md rules.yaml ./
COPY safeexec ./safeexec
RUN pip install --no-cache-dir .
RUN useradd --create-home --uid 10001 safeexec
USER safeexec
ENTRYPOINT ["safe-exec-service"]
