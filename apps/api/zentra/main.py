"""Zentra API application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from zentra import __version__
from zentra.api.errors import register_exception_handlers
from zentra.api.middleware import (
    BodySizeLimitMiddleware,
    GlobalRateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from zentra.api.schemas import HealthResponse, ReadinessResponse
from zentra.api.v1.router import api_router
from zentra.config import Settings, get_settings
from zentra.core.ratelimit import redis_available
from zentra.db.session import ping as db_ping
from zentra.logging import configure_logging, get_logger

DESCRIPTION = """
Zentra continuously assesses your third-party vendors against security signals
available from public sources, and turns the result into a 0–100 risk score, a
plain-English explanation and an auditor-friendly vendor risk register.

## Authentication

Two schemes are supported.

* **Session token** — `Authorization: Bearer <access_token>`, obtained from
  `POST /api/v1/auth/signin`. Used by the Zentra dashboard.
* **API key** — `X-API-Key: zk_live_...`, available on the Scale plan. Create
  keys at `POST /api/v1/api-keys`. The secret is shown once and stored only as
  a hash.

Send `X-Zentra-Organization: <uuid>` to act on a specific organization when
your account belongs to more than one. Without it, your first organization is
used.

## Errors

Every error uses one envelope:

```json
{
  "error": {
    "code": "VENDOR_NOT_FOUND",
    "message": "Vendor could not be found.",
    "request_id": "8f0c..."
  }
}
```

Quote the `request_id` when contacting support.

## Rate limits

| Surface | Default limit |
| --- | --- |
| Public free scan | 3 per hour per requester |
| Authentication | 10 per 15 minutes per IP and per account |
| Manual scan triggers | 20 per hour per organization |
| Report generation | 10 per hour per organization |
| API (Growth) | 60 requests per minute |
| API (Scale) | 300 requests per minute |

Exceeding a limit returns `429` with a `Retry-After` header.

## Scanning policy

Zentra performs passive checks against publicly available sources only. It does
not attempt authentication, exploitation or intrusive testing against any
vendor. Domains that resolve to private, loopback, link-local or cloud-metadata
address space are refused.

## Important

Zentra's risk scores are informational assessments based on signals from
publicly available sources. They are not an audit of the vendor and are not
legal, regulatory or certification advice.
"""

TAGS_METADATA = [
    {"name": "Authentication", "description": "Sign up, sign in and invitations."},
    {"name": "Account", "description": "The current user, organization, members and dashboard."},
    {"name": "Vendors", "description": "Manage the vendors you monitor."},
    {"name": "Scans", "description": "Scan records and their normalized check results."},
    {"name": "Findings", "description": "Deduplicated findings and remediation tracking."},
    {"name": "Reports", "description": "Vendor risk register PDF generation and download."},
    {"name": "Alerts", "description": "Material risk changes and their delivery status."},
    {"name": "Billing", "description": "Plans, Stripe Checkout and the customer portal."},
    {"name": "API keys", "description": "Issue and revoke keys for the public API."},
    {
        "name": "Public API (API key)",
        "description": "Stable integration surface for Scale customers.",
    },
    {"name": "Public", "description": "Unauthenticated free scan."},
    {"name": "Integrations", "description": "Slack and Microsoft Teams."},
    {"name": "Benchmarking", "description": "Anonymized cohort comparison."},
    {"name": "Webhooks", "description": "Inbound provider callbacks."},
    {"name": "System", "description": "Health and readiness probes."},
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    log = get_logger("zentra.startup")
    log.info(
        "api_starting",
        version=__version__,
        environment=settings.environment,
        auth_provider=settings.auth_provider,
        mock_scanners=settings.use_mock_scanners,
    )
    if settings.is_production and settings.use_mock_scanners:  # pragma: no cover
        raise RuntimeError("Mock scanners must never be enabled in production.")
    yield
    log.info("api_stopping")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format, service=settings.service_name)

    app = FastAPI(
        title="Zentra API",
        description=DESCRIPTION,
        version=__version__,
        openapi_tags=TAGS_METADATA,
        lifespan=lifespan,
        # Interactive docs are disabled in production; the schema is published
        # separately as part of the developer documentation.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None if settings.is_production else "/redoc",
        openapi_url="/openapi.json",
        contact={"name": "Zentra", "url": settings.app_url},
        license_info={"name": "Proprietary"},
        servers=[{"url": settings.api_url, "description": settings.environment}],
    )

    # Middleware runs bottom-up: context is outermost so every other layer has
    # a request ID available.
    app.add_middleware(GlobalRateLimitMiddleware)
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(
        CORSMiddleware,
        # Explicit origins only. A wildcard is rejected by the settings
        # validator in production.
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-Zentra-Organization",
            "X-Request-ID",
        ],
        expose_headers=[
            "X-Request-ID",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "Retry-After",
        ],
        max_age=600,
    )
    if settings.is_production:  # pragma: no cover - production hardening
        from urllib.parse import urlparse

        host = urlparse(settings.api_url).hostname
        if host:
            app.add_middleware(TrustedHostMiddleware, allowed_hosts=[host, f"*.{host}"])
    app.add_middleware(RequestContextMiddleware)

    register_exception_handlers(app)
    app.include_router(api_router)

    @app.get("/health", response_model=HealthResponse, tags=["System"], summary="Liveness probe")
    async def health() -> HealthResponse:
        """Cheap liveness check. Touches no dependency."""
        return HealthResponse(status="ok", version=__version__, environment=settings.environment)

    @app.get(
        "/ready",
        response_model=ReadinessResponse,
        tags=["System"],
        summary="Readiness probe",
        responses={503: {"description": "A required dependency is unavailable."}},
    )
    async def ready() -> Any:
        """Verifies the database and Redis are reachable."""
        from starlette.responses import JSONResponse

        checks = {
            "database": "ok" if db_ping() else "unavailable",
            "redis": "ok" if redis_available() else "unavailable",
        }
        healthy = all(v == "ok" for v in checks.values())
        payload = ReadinessResponse(status="ready" if healthy else "degraded", checks=checks)
        if not healthy:
            return JSONResponse(status_code=503, content=payload.model_dump())
        return payload

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {
            "service": "zentra-api",
            "version": __version__,
            "documentation": "/docs" if not settings.is_production else "/openapi.json",
        }

    return app


app = create_app()
