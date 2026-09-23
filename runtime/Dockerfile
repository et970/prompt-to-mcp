# Generic MCP runtime image. Built ONCE and reused for every generated MCP
# server; the manifest is supplied at deploy time via environment variables, so
# provisioning a new MCP never requires a container build.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin mcp
USER 10001

ENV PORT=8080
EXPOSE 8080

CMD ["python", "server.py"]
