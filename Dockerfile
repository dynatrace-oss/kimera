FROM python:3.13-slim AS base

LABEL org.opencontainers.image.source="https://github.com/dynatrace-oss/kimera"
LABEL org.opencontainers.image.description="K8s security testing toolkit with MCP server"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN groupadd -r kimera && useradd -r -g kimera -d /app kimera

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY kimera/ kimera/
COPY config/ config/

RUN pip install --no-cache-dir uv && \
    uv pip install --system -e '.[mcp-server]' && \
    pip uninstall -y uv

USER kimera

ENTRYPOINT ["kimera"]
