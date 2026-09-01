"""Transactional email templates and send helpers."""

from __future__ import annotations

import html
from typing import Any

from zentra.config import get_settings
from zentra.db.models import Alert, Organization, User, Vendor
from zentra.integrations.email.provider import EmailMessage, get_email_provider
from zentra.logging import get_logger

log = get_logger("zentra.email.service")

_BASE_STYLE = (
    "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;"
    "color:#111318;line-height:1.55;"
)


def _wrap(title: str, body_html: str, cta_label: str | None, cta_url: str | None) -> str:
    cta = ""
    if cta_label and cta_url:
        cta = (
            f'<p style="margin:28px 0"><a href="{html.escape(cta_url)}" '
            'style="background:#111318;color:#fff;text-decoration:none;padding:12px 22px;'
            'border-radius:2px;display:inline-block;font-weight:600;font-size:14px">'
            f"{html.escape(cta_label)}</a></p>"
        )
    return (
        f'<div style="{_BASE_STYLE}max-width:560px;margin:0 auto;padding:32px 20px">'
        '<div style="font-weight:700;letter-spacing:.22em;font-size:12px;color:#6b7280;'
        'text-transform:uppercase;margin-bottom:24px">ZENTRA</div>'
        f'<h1 style="font-size:20px;margin:0 0 16px;font-weight:650">{html.escape(title)}</h1>'
        f"{body_html}{cta}"
        '<hr style="border:none;border-top:1px solid #e5e7eb;margin:32px 0 16px">'
        '<p style="font-size:12px;color:#6b7280;margin:0">'
        "Zentra's risk scores are informational assessments based on signals from publicly "
        "available sources. They are not an audit of the vendor and are not legal, regulatory "
        "or certification advice.</p></div>"
    )


def _send(
    to: list[str],
    subject: str,
    title: str,
    paragraphs: list[str],
    *,
    cta_label: str | None = None,
    cta_url: str | None = None,
    tags: dict[str, str] | None = None,
) -> str:
    body_html = "".join(
        f'<p style="margin:0 0 14px;font-size:15px">{html.escape(p)}</p>' for p in paragraphs
    )
    text = "\n\n".join([title, *paragraphs])
    if cta_url:
        text += f"\n\n{cta_label or 'Open Zentra'}: {cta_url}"
    message = EmailMessage(
        to=to,
        subject=subject[:200],
        html=_wrap(title, body_html, cta_label, cta_url),
        text=text,
        tags=tags or {},
    )
    return get_email_provider().send(message)


def send_welcome(*, user: User, organization: Organization) -> str:
    settings = get_settings()
    return _send(
        [user.email],
        "Welcome to Zentra",
        "Your Zentra workspace is ready",
        [
            f"Hi{' ' + user.full_name.split()[0] if user.full_name else ''}, "
            f"{organization.name} is set up on Zentra.",
            "Add your first vendor and Zentra will assess it against publicly available "
            "security signals, then keep monitoring it and alert you if the picture changes.",
        ],
        cta_label="Add your first vendor",
        cta_url=f"{settings.app_url}/dashboard/vendors/new",
        tags={"type": "welcome"},
    )


def send_scan_completed(
    *, to: list[str], vendor: Vendor, score: int | None, risk_level: str | None, headline: str
) -> str:
    settings = get_settings()
    score_line = (
        f"{vendor.name} scored {score}/100 ({risk_level} risk)."
        if score is not None and risk_level
        else f"Zentra could not complete enough checks to score {vendor.name} this time."
    )
    return _send(
        to,
        f"Scan complete: {vendor.name}",
        f"Assessment complete for {vendor.name}",
        [score_line, headline],
        cta_label="View the assessment",
        cta_url=f"{settings.app_url}/dashboard/vendors/{vendor.id}",
        tags={"type": "scan_completed"},
    )


def send_risk_alert(
    *, alert: Alert, vendor: Vendor | None, organization: Organization, to: list[str]
) -> str:
    settings = get_settings()
    paragraphs = [alert.message]
    if alert.score_delta:
        paragraphs.append(
            f"Score change: {alert.old_score} → {alert.new_score} "
            f"({'+' if alert.score_delta > 0 else ''}{alert.score_delta} points)."
        )
    paragraphs.append(
        "Review the vendor in Zentra to see which signals changed and what to ask the vendor."
    )
    url = (
        f"{settings.app_url}/dashboard/vendors/{vendor.id}"
        if vendor
        else f"{settings.app_url}/dashboard"
    )
    return _send(
        to,
        f"[Zentra] {alert.title}",
        alert.title,
        paragraphs,
        cta_label="Review the vendor",
        cta_url=url,
        tags={"type": "risk_alert", "severity": alert.severity},
    )


def send_weekly_summary(
    *, to: list[str], organization: Organization, summary: dict[str, Any]
) -> str:
    settings = get_settings()
    return _send(
        to,
        f"Your weekly vendor risk summary — {organization.name}",
        "Weekly vendor risk summary",
        [
            f"You are monitoring {summary.get('total_vendors', 0)} vendors.",
            f"{summary.get('vendors_needing_attention', 0)} need attention "
            f"({summary.get('critical_vendors', 0)} critical, "
            f"{summary.get('high_risk_vendors', 0)} high risk).",
            f"{summary.get('open_findings', 0)} findings are still open.",
        ],
        cta_label="Open your dashboard",
        cta_url=f"{settings.app_url}/dashboard",
        tags={"type": "weekly_summary"},
    )


def send_invitation(*, to_email: str, organization: Organization, token: str, inviter: User) -> str:
    settings = get_settings()
    return _send(
        [to_email],
        f"You have been invited to {organization.name} on Zentra",
        f"Join {organization.name} on Zentra",
        [
            f"{inviter.full_name or inviter.email} invited you to collaborate on "
            f"{organization.name}'s vendor risk register.",
            "This invitation expires in 7 days.",
        ],
        cta_label="Accept the invitation",
        cta_url=f"{settings.app_url}/auth/accept-invite?token={token}",
        tags={"type": "invitation"},
    )


def send_subscription_changed(
    *, to: list[str], organization: Organization, plan: str, status: str
) -> str:
    settings = get_settings()
    return _send(
        to,
        f"Your Zentra plan is now {plan.title()}",
        f"Plan updated: {plan.title()}",
        [
            f"{organization.name}'s Zentra subscription is now on the {plan.title()} plan "
            f"({status}).",
            "Your vendor limit and available features have been updated.",
        ],
        cta_label="View billing",
        cta_url=f"{settings.app_url}/dashboard/billing",
        tags={"type": "subscription_changed"},
    )
