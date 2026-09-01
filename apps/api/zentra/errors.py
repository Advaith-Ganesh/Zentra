"""Consistent application error taxonomy and API error envelope."""

from __future__ import annotations

from typing import Any


class ZentraError(Exception):
    """Base class for errors that map onto a structured API response."""

    status_code: int = 500
    code: str = "INTERNAL_ERROR"
    message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message or self.message
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)

    def to_payload(self, request_id: str | None = None) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            error["details"] = self.details
        if request_id:
            error["request_id"] = request_id
        return {"error": error}


class ValidationError(ZentraError):
    status_code = 422
    code = "VALIDATION_ERROR"
    message = "The request payload failed validation."


class AuthenticationError(ZentraError):
    status_code = 401
    code = "UNAUTHENTICATED"
    message = "Authentication is required."


class InvalidCredentialsError(AuthenticationError):
    code = "INVALID_CREDENTIALS"
    message = "Email or password is incorrect."


class PermissionDeniedError(ZentraError):
    status_code = 403
    code = "PERMISSION_DENIED"
    message = "You do not have permission to perform this action."


class NotFoundError(ZentraError):
    status_code = 404
    code = "NOT_FOUND"
    message = "The requested resource could not be found."


class VendorNotFoundError(NotFoundError):
    code = "VENDOR_NOT_FOUND"
    message = "Vendor could not be found."


class ConflictError(ZentraError):
    status_code = 409
    code = "CONFLICT"
    message = "The resource already exists."


class DuplicateVendorError(ConflictError):
    code = "VENDOR_ALREADY_EXISTS"
    message = "A vendor with this domain already exists in your organization."


class RateLimitedError(ZentraError):
    status_code = 429
    code = "RATE_LIMITED"
    message = "Too many requests. Please try again later."

    def __init__(self, message: str | None = None, *, retry_after: int = 60) -> None:
        super().__init__(message, details={"retry_after_seconds": retry_after})
        self.retry_after = retry_after


class EntitlementError(ZentraError):
    status_code = 402
    code = "PLAN_LIMIT_REACHED"
    message = "Your current plan does not include this capability."


class FeatureDisabledError(ZentraError):
    status_code = 404
    code = "FEATURE_DISABLED"
    message = "This feature is not enabled."


class UnsafeTargetError(ZentraError):
    """Raised when a scan target resolves to a network we must never touch."""

    status_code = 400
    code = "UNSAFE_SCAN_TARGET"
    message = "The supplied domain cannot be scanned."


class InvalidDomainError(ZentraError):
    status_code = 422
    code = "INVALID_DOMAIN"
    message = "The supplied domain is not a valid public domain name."


class ProviderError(ZentraError):
    """An upstream security data provider failed. Never a security verdict."""

    status_code = 502
    code = "PROVIDER_ERROR"
    message = "An upstream security data provider is unavailable."


class ServiceUnavailableError(ZentraError):
    status_code = 503
    code = "SERVICE_UNAVAILABLE"
    message = "A required dependency is unavailable."
