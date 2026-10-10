# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Semgrep lives in its own virtualenv so its pinned deps never clash with the API's.
RUN python -m venv /opt/semgrep && /opt/semgrep/bin/pip install semgrep==1.179.0 \
 && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY codeguard ./codeguard
COPY server.py .

RUN useradd --create-home --uid 10001 codeguard
USER codeguard
EXPOSE 8000
# Probe the port the platform assigned ($PORT), not a hardcoded 8000, or the container is marked unhealthy.
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT', '8000'), timeout=4)"
CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000}"]
