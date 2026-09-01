"""Structured logging with request correlation and secret redaction."""

from __future__ import annotations

import contextvars
import logging
import re
import sys
from typing import Any

import structlog

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "zentra_request_id", default=None
)
organization_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "zentra_org_id", default=None
)

# Keys whose values must never reach a log sink.
SENSITIVE_KEYS = frozenset(
    {
        "password",
        "current_password",
        "new_password",
        "password_hash",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "bot_token",
        "api_key",
        "apikey",
        "key",
        "secret",
        "client_secret",
        "signing_secret",
        "service_role_key",
        "anon_key",
        "authorization",
        "cookie",
        "set-cookie",
        "stripe_signature",
        "webhook_secret",
        "jwt_secret",
        "encryption_key",
        "webhook_url",
        "breach_records",
        "raw_breach_data",
    }
)

_SECRET_PATTERNS = [
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{6,}"),
    re.compile(r"\bwhsec_[A-Za-z0-9]{6,}"),
    re.compile(r"\bxox[bpsa]-[A-Za-z0-9-]{6,}"),
    re.compile(r"\bre_[A-Za-z0-9_]{12,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"\bzk_[A-Za-z0-9_-]{12,}"),
]

REDACTED = "[redacted]"


def _scrub_value(value: Any) -> Any:
    if isinstance(value, str):
        out = value
        for pattern in _SECRET_PATTERNS:
            out = pattern.sub(REDACTED, out)
        return out
    if isinstance(value, dict):
        return _scrub_mapping(value)
    if isinstance(value, list | tuple):
        return type(value)(_scrub_value(v) for v in value)
    return value


def _scrub_mapping(mapping: dict[Any, Any]) -> dict[Any, Any]:
    out: dict[Any, Any] = {}
    for k, v in mapping.items():
        if isinstance(k, str) and k.lower() in SENSITIVE_KEYS:
            out[k] = REDACTED
        else:
            out[k] = _scrub_value(v)
    return out


def redaction_processor(_logger: Any, _name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    return _scrub_mapping(event_dict)


def context_processor(_logger: Any, _name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    rid = request_id_var.get()
    if rid:
        event_dict.setdefault("request_id", rid)
    org = organization_id_var.get()
    if org:
        event_dict.setdefault("organization_id", org)
    return event_dict


_configured = False


def configure_logging(level: str = "INFO", fmt: str = "console", service: str = "zentra") -> None:
    global _configured
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        context_processor,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        redaction_processor,
    ]
    if fmt == "json":
        processors.append(structlog.processors.format_exc_info)
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()))

    logging.basicConfig(
        format="%(message)s", stream=sys.stdout, level=getattr(logging, level.upper(), logging.INFO)
    )
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    structlog.contextvars.bind_contextvars(service=service)
    _configured = True


def get_logger(name: str | None = None) -> Any:
    if not _configured:
        configure_logging()
    return structlog.get_logger(name or "zentra")
