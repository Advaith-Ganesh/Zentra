"""Exception handlers producing Zentra's single error envelope."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from zentra.config import get_settings
from zentra.errors import RateLimitedError, ZentraError
from zentra.logging import get_logger, request_id_var

log = get_logger("zentra.api.errors")


def _envelope(code: str, message: str, details: dict | None = None) -> dict:
    error: dict = {"code": code, "message": message}
    if details:
        error["details"] = details
    error["request_id"] = request_id_var.get()
    return {"error": error}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ZentraError)
    async def _zentra_error(request: Request, exc: ZentraError) -> JSONResponse:
        headers = {}
        if isinstance(exc, RateLimitedError):
            headers["Retry-After"] = str(exc.retry_after)
        if exc.status_code >= 500:
            log.error(
                "api_error",
                code=exc.code,
                status=exc.status_code,
                path=request.url.path,
                error_type=type(exc).__name__,
            )
        else:
            log.info(
                "api_client_error", code=exc.code, status=exc.status_code, path=request.url.path
            )
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_payload(request_id_var.get()),
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = []
        for error in exc.errors()[:20]:
            location = ".".join(str(part) for part in error.get("loc", ())[1:])
            fields.append({"field": location or "body", "message": error.get("msg", "invalid")})
        return JSONResponse(
            status_code=422,
            content=_envelope(
                "VALIDATION_ERROR",
                "The request payload failed validation.",
                {"fields": fields},
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        codes = {
            400: "BAD_REQUEST",
            401: "UNAUTHENTICATED",
            403: "PERMISSION_DENIED",
            404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            409: "CONFLICT",
            413: "PAYLOAD_TOO_LARGE",
            415: "UNSUPPORTED_MEDIA_TYPE",
            429: "RATE_LIMITED",
        }
        code = codes.get(exc.status_code, "HTTP_ERROR")
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(code, detail),
            headers=getattr(exc, "headers", None) or {},
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Log the type and traceback server-side; never expose either.
        log.exception(
            "unhandled_exception",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
        )
        settings = get_settings()
        message = "An unexpected error occurred. The incident has been logged."
        details = None
        if settings.debug and not settings.is_production:
            details = {"debug_error_type": type(exc).__name__}
        return JSONResponse(status_code=500, content=_envelope("INTERNAL_ERROR", message, details))
