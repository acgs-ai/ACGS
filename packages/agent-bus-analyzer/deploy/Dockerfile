# syntax=docker/dockerfile:1.7
#
# agent-bus-analyzer API image.
#
# This package is observer/query-only: it serves already captured trace store
# files and never authorizes agent actions. The Cloud Run manifest supplies
# deployment-managed signing material for receipt exports.

FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8080
ENV AGENT_BUS_ANALYZER_STORE_DIR=/var/lib/agent-bus-analyzer
ENV ANALYZER_UID=10001
ENV ANALYZER_GID=10001

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir . \
    && addgroup --system --gid ${ANALYZER_GID} analyzer \
    && adduser --system --uid ${ANALYZER_UID} --ingroup analyzer analyzer \
    && mkdir -p "${AGENT_BUS_ANALYZER_STORE_DIR}" \
    && chown -R ${ANALYZER_UID}:${ANALYZER_GID} "${AGENT_BUS_ANALYZER_STORE_DIR}"

USER ${ANALYZER_UID}:${ANALYZER_GID}

EXPOSE 8080

CMD ["agent-bus-analyzer", "serve", "--host", "0.0.0.0", "--port", "8080", "--store-dir", "/var/lib/agent-bus-analyzer"]
