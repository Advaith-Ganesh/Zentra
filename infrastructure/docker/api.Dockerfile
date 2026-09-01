# =============================================================================
# Zentra API / worker image
# =============================================================================
# One image serves both the FastAPI process and the Celery worker; the command
# decides which. That keeps the two in lockstep — a worker can never run a
# different version of the scanning code than the API that queued the job.
# =============================================================================
FROM python:3.11-slim-bookworm AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# WeasyPrint needs Pango/Cairo at runtime, not just at build time.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpango-1.0-0 \
      libpangoft2-1.0-0 \
      libcairo2 \
      libgdk-pixbuf-2.0-0 \
      libffi8 \
      shared-mime-info \
      fonts-dejavu-core \
      curl \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---------------------------------------------------------------- dependencies
FROM base AS deps
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY apps/api/pyproject.toml /app/apps/api/pyproject.toml
COPY apps/api/zentra/__init__.py /app/apps/api/zentra/__init__.py
RUN pip install --prefix=/install /app/apps/api

# --------------------------------------------------------------------- runtime
FROM base AS runtime

# Run as an unprivileged user. The scanner makes outbound requests on behalf of
# users, so the process should hold as little as possible.
RUN useradd --create-home --uid 10001 zentra

COPY --from=deps /install /usr/local
COPY apps/api /app/apps/api
COPY supabase/migrations /app/supabase/migrations

RUN mkdir -p /app/storage/reports && chown -R zentra:zentra /app/storage
WORKDIR /app/apps/api
USER zentra

ENV PYTHONPATH=/app/apps/api \
    REPORT_STORAGE_DIR=/app/storage/reports

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# Railway and Docker Compose both override this for the worker process.
CMD ["sh", "-c", "uvicorn zentra.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
