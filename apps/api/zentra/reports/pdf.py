"""PDF rendering with WeasyPrint.

White-label branding is customer-supplied, so it is sanitized hard: the logo is
re-decoded and re-encoded as a data URI (never fetched at render time, which
would be an SSRF vector), the brand colour must match a strict hex pattern, and
all text is escaped by Jinja's autoescaping.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from zentra.logging import get_logger

log = get_logger("zentra.reports.pdf")

TEMPLATE_DIR = Path(__file__).parent / "templates"

_HEX_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")

#: Only raster formats we can validate by magic bytes.
ALLOWED_LOGO_TYPES: dict[str, bytes] = {
    "image/png": b"\x89PNG\r\n\x1a\n",
    "image/jpeg": b"\xff\xd8\xff",
    "image/gif": b"GIF8",
}

_environment = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def sanitize_color(value: str | None) -> str | None:
    """Accept only a literal hex colour. Anything else is dropped.

    This is what stops a branding field from injecting CSS into the report.
    """
    if not value or not isinstance(value, str):
        return None
    candidate = value.strip()
    return candidate if _HEX_COLOR_RE.match(candidate) else None


def sanitize_logo(data: bytes | None, *, max_bytes: int) -> tuple[str | None, str | None]:
    """Validate an uploaded logo and return ``(data_uri, error)``.

    The file is identified by its magic bytes, not by its filename or the
    declared content type, and is embedded as a data URI so rendering never
    makes a network request.
    """
    if not data:
        return None, None
    if len(data) > max_bytes:
        return None, f"The logo must be {max_bytes // 1024} KB or smaller."
    for mime, magic in ALLOWED_LOGO_TYPES.items():
        if data.startswith(magic):
            encoded = base64.b64encode(data).decode("ascii")
            return f"data:{mime};base64,{encoded}", None
    return None, "The logo must be a PNG, JPEG or GIF image."


def build_branding(
    *,
    white_label_allowed: bool,
    branding: dict[str, Any] | None,
    organization_name: str,
) -> dict[str, Any]:
    """Resolve the brand block used by the report template."""
    default = {
        "name": "Zentra",
        "wordmark": "ZENTRA",
        "prepared_by": "Zentra",
        "color": None,
        "logo_data_uri": None,
    }
    if not white_label_allowed or not branding:
        return default

    name = str(branding.get("company_name") or organization_name)[:80]
    return {
        "name": name,
        "wordmark": name.upper()[:40],
        "prepared_by": f"{name} using Zentra",
        "color": sanitize_color(branding.get("brand_color")),
        # Already validated and stored as a data URI at upload time.
        "logo_data_uri": _safe_stored_logo(branding.get("logo_data_uri")),
    }


def _safe_stored_logo(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 1_400_000:
        return None
    if not value.startswith(
        ("data:image/png;base64,", "data:image/jpeg;base64,", "data:image/gif;base64,")
    ):
        return None
    return value


def render_html(context: dict[str, Any], template_name: str = "report.html") -> str:
    return _environment.get_template(template_name).render(**context)


def render_pdf(context: dict[str, Any], template_name: str = "report.html") -> bytes:
    """Render the report to PDF bytes."""
    from weasyprint import HTML

    html = render_html(context, template_name)
    # base_url is deliberately None: with no base URL WeasyPrint cannot resolve
    # any relative external resource, so a crafted template value cannot cause
    # an outbound fetch. All assets are inline data URIs.
    return HTML(string=html, base_url=None).write_pdf()
