# jarvis-tools: the MCP server Hermes calls for Jarvis's specialist agents.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN useradd --uid 10001 --system --no-create-home --shell /usr/sbin/nologin tools
COPY requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir --no-deps -r /app/requirements.lock && pip check
COPY app/ /app/
COPY specialists/ /app/specialists/
USER 10001
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/app/server.py"]
