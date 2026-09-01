"""Email delivery providers.

The console provider is the default in development: it logs the message
(with the body truncated and headers redacted) instead of sending it, so the
whole product works with no email credential.
"""

from __future__ import annotations

import abc
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from zentra.config import get_settings
from zentra.errors import ZentraError
from zentra.logging import get_logger

log = get_logger("zentra.email")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


class EmailDeliveryError(ZentraError):
    status_code = 502
    code = "EMAIL_DELIVERY_FAILED"
    message = "The email could not be delivered."


@dataclass
class EmailMessage:
    to: list[str]
    subject: str
    html: str
    text: str
    reply_to: str | None = None
    tags: dict[str, str] = field(default_factory=dict)

    def validated_recipients(self) -> list[str]:
        return [r for r in self.to if _EMAIL_RE.match(r or "")][:50]


class EmailProvider(abc.ABC):
    name = "email"

    @abc.abstractmethod
    def send(self, message: EmailMessage) -> str:
        """Send the message. Returns a provider message ID."""


class ConsoleEmailProvider(EmailProvider):
    """Logs emails rather than sending them. Used in development and tests."""

    name = "console"

    #: Test/dev inspection buffer. Bounded so a long dev session cannot grow it
    #: without limit.
    outbox: list[EmailMessage] = []
    MAX_OUTBOX = 200

    def send(self, message: EmailMessage) -> str:
        recipients = message.validated_recipients()
        if not recipients:
            raise EmailDeliveryError("No valid recipient addresses.")
        ConsoleEmailProvider.outbox.append(message)
        if len(ConsoleEmailProvider.outbox) > self.MAX_OUTBOX:
            del ConsoleEmailProvider.outbox[: -self.MAX_OUTBOX]
        log.info(
            "email_logged_not_sent",
            recipient_count=len(recipients),
            subject=message.subject,
            provider="console",
        )
        return f"console-{len(ConsoleEmailProvider.outbox)}"

    @classmethod
    def clear(cls) -> None:
        cls.outbox.clear()


class ResendEmailProvider(EmailProvider):
    """Resend HTTP API client."""

    name = "resend"
    API_URL = "https://api.resend.com/emails"

    def __init__(self, *, api_key: str | None = None, sender: str | None = None) -> None:
        settings = get_settings()
        self.api_key = api_key if api_key is not None else settings.resend_api_key
        self.sender = sender or settings.email_from
        self.timeout = 10.0

    def send(self, message: EmailMessage) -> str:
        if not self.api_key:
            raise EmailDeliveryError(
                "RESEND_API_KEY is not configured.", code="EMAIL_NOT_CONFIGURED"
            )
        recipients = message.validated_recipients()
        if not recipients:
            raise EmailDeliveryError("No valid recipient addresses.")

        payload: dict[str, Any] = {
            "from": self.sender,
            "to": recipients,
            "subject": message.subject[:200],
            "html": message.html,
            "text": message.text,
        }
        if message.reply_to:
            payload["reply_to"] = message.reply_to
        if message.tags:
            payload["tags"] = [{"name": k, "value": v} for k, v in list(message.tags.items())[:5]]

        try:
            response = httpx.post(
                self.API_URL,
                json=payload,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            raise EmailDeliveryError(f"Email transport failed: {type(exc).__name__}") from exc

        if response.status_code >= 400:
            # Never log the response body: it can echo recipient addresses.
            log.warning("email_send_failed", status=response.status_code, provider="resend")
            raise EmailDeliveryError(f"Email provider returned HTTP {response.status_code}.")
        try:
            return str(response.json().get("id", ""))
        except ValueError:
            return ""


def get_email_provider() -> EmailProvider:
    settings = get_settings()
    if settings.email_provider == "resend" and settings.resend_api_key:
        return ResendEmailProvider()
    return ConsoleEmailProvider()
