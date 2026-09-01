"""HTTP middleware: request IDs, security headers, body limits, rate limiting."""

from __future__ import annotations

import time
import uuid

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from zentra.config import get_settings
from zentra.core.ratelimit import check_rate_limit
from zentra.core.security import pseudonymize
from zentra.logging import get_logger, organization_id_var, request_id_var

log = get_logger("zentra.http")

MAX_BODY_BYTES = 1_000_000  # 1 MB; report logo uploads have their own limit.

#: Endpoints that are exempt from the body-size limit (they take file uploads).
UPLOAD_PATHS = ("/api/v1/organization/branding/logo",)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request ID, times the request and logs an access record."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming[:64] if incoming.isascii() and len(incoming) <= 64 else ""
        request_id = request_id or uuid.uuid4().hex
        token = request_id_var.set(request_id)
        org_token = organization_id_var.set(None)
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            duration_ms = int((time.perf_counter() - started) * 1000)
            request_id_var.reset(token)
            organization_id_var.reset(org_token)
        response.headers["X-Request-ID"] = request_id
        log.info(
            "http_request",
            method=request.method,
            # Only the route template and path are logged; query strings can
            # carry customer data.
            path=request.url.path,
            status=response.status_code,
            duration_ms=duration_ms,
            request_id=request_id,
        )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Applies defence-in-depth response headers to every API response."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        settings = get_settings()
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-site",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=(), interest-cohort=()",
            # The API serves JSON and PDFs, never HTML with scripts.
            "Content-Security-Policy": (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            ),
            "Cache-Control": "no-store",
        }
        if settings.is_production:
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        for key, value in headers.items():
            response.headers.setdefault(key, value)
        # Docs pages need to load their own bundle and styles.
        if request.url.path in ("/docs", "/redoc", "/openapi.json"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data: https://fastapi.tiangolo.com; "
                "script-src 'self' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "frame-ancestors 'none'"
            )
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects oversized request bodies before they are parsed."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path not in UPLOAD_PATHS:
            declared = request.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": {
                            "code": "PAYLOAD_TOO_LARGE",
                            "message": "The request body is too large.",
                            "request_id": request_id_var.get(),
                        }
                    },
                )
        return await call_next(request)


class GlobalRateLimitMiddleware(BaseHTTPMiddleware):
    """A coarse per-client ceiling on top of the per-endpoint limiters."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        settings = get_settings()
        if not settings.rate_limit_enabled or request.url.path in ("/health", "/ready"):
            return await call_next(request)

        limit, window = settings.rate("api")
        identifier = client_identifier(request)
        result = check_rate_limit("global", identifier, limit, window)
        if not result.allowed:
            log.warning("rate_limited", bucket="global", path=request.url.path)
            return JSONResponse(
                status_code=429,
                headers={
                    "Retry-After": str(result.retry_after),
                    "X-RateLimit-Limit": str(result.limit),
                    "X-RateLimit-Remaining": "0",
                },
                content={
                    "error": {
                        "code": "RATE_LIMITED",
                        "message": "Too many requests. Please try again shortly.",
                        "request_id": request_id_var.get(),
                    }
                },
            )
        response = await call_next(request)
        response.headers.setdefault("X-RateLimit-Limit", str(result.limit))
        response.headers.setdefault("X-RateLimit-Remaining", str(result.remaining))
        return response


def client_ip(request: Request) -> str:
    """Best-effort client IP.

    ``X-Forwarded-For`` is only trusted when the deployment sits behind a proxy
    that sets it (Railway, Vercel). The leftmost entry is used, and it is only
    ever consumed for rate limiting, never for an authorization decision.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        candidate = forwarded.split(",")[0].strip()
        if candidate and len(candidate) <= 45:
            return candidate
    return request.client.host if request.client else "unknown"


def client_identifier(request: Request) -> str:
    """A pseudonymous, stable identifier for rate limiting."""
    principal = getattr(request.state, "principal", None)
    if principal is not None:
        return f"org:{principal.organization.id}"
    api_key = request.headers.get("x-api-key")
    if api_key:
        return f"key:{pseudonymize(api_key)}"
    return f"ip:{pseudonymize(client_ip(request))}"
