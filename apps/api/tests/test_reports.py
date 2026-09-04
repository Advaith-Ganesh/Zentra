"""PDF report generation, white-label branding and download safety."""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import Account
from zentra.reports.pdf import build_branding, render_pdf, sanitize_color, sanitize_logo


def _png(size: int = 200) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + b"\x00" * size


def _minimal_context(**overrides) -> dict:
    context = {
        "title": "Vendor Risk Register",
        "report_id": str(uuid.uuid4()),
        "organization": {"name": "Acme Fintech"},
        "brand": build_branding(
            white_label_allowed=False, branding=None, organization_name="Acme Fintech"
        ),
        "generated_at_display": "01 September 2026",
        "generated_at": "2026-09-01T00:00:00Z",
        "period": "As at 01 September 2026",
        "requested_by": "Ada Lovelace",
        "summary": {
            "total_vendors": 1,
            "critical_vendors": 0,
            "high_risk_vendors": 1,
            "average_score": 55.0,
            "open_findings": 2,
            "vendors_needing_attention": 1,
        },
        "unscored_vendors": 0,
        "vendors": [
            {
                "name": "Acme Payments",
                "domain": "acme-payments.io",
                "category": "Payments",
                "criticality": "critical",
                "owner": "Ada Lovelace",
                "score": 55,
                "risk_level": "high",
                "last_assessed": "01 September 2026",
                "key_findings": ["Expired TLS certificate"],
                "recommended_action": "Ask the vendor to renew their certificate.",
                "verdict": {"explanation": "Zentra detected signals associated with risk."},
                "breakdown": [
                    {
                        "display_name": "TLS / certificate",
                        "points": 25,
                        "max_points": 25,
                        "assessed": True,
                        "pct": 100,
                    }
                ],
                "unassessed": ["Known vulnerabilities"],
                "findings": [
                    {
                        "title": "Expired TLS certificate",
                        "description": "The certificate expired 3 days ago.",
                        "recommendation": "Ask the vendor to renew it.",
                        "severity": "critical",
                        "status_label": "Open",
                        "source": "ssllabs",
                        "first_seen": "29 August 2026",
                        "last_seen": "01 September 2026",
                        "confidence": "100%",
                    }
                ],
            }
        ],
    }
    context.update(overrides)
    return context


# --------------------------------------------------------------- sanitization
@pytest.mark.parametrize("value", ["#fff", "#FFFFFF", "#1a1a1a", "#0B0C0E"])
def test_valid_hex_colours_are_accepted(value: str) -> None:
    assert sanitize_color(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "red",
        "rgb(1,2,3)",
        "#12345",
        "#GGGGGG",
        "#fff; } body { display:none } .x {",
        "expression(alert(1))",
        "url(https://evil.example/x.png)",
        "</style><script>alert(1)</script>",
        "",
        None,
    ],
)
def test_unsafe_colour_values_are_dropped(value) -> None:
    assert sanitize_color(value) is None


def test_logo_is_identified_by_magic_bytes_not_filename() -> None:
    data_uri, error = sanitize_logo(_png(), max_bytes=100_000)
    assert error is None
    assert data_uri.startswith("data:image/png;base64,")


@pytest.mark.parametrize(
    "payload",
    [
        b"<svg onload=alert(1)></svg>",
        b"<?php system($_GET[0]); ?>",
        b"GIF8",  # truncated but valid magic: accepted, see separate test
        b"not an image at all",
        b"\x00\x01\x02\x03",
    ],
)
def test_non_raster_uploads_are_rejected(payload: bytes) -> None:
    data_uri, error = sanitize_logo(payload, max_bytes=100_000)
    if payload.startswith(b"GIF8"):
        assert data_uri is not None
    else:
        assert data_uri is None
        assert error


def test_oversized_logo_is_rejected() -> None:
    data_uri, error = sanitize_logo(_png(200_000), max_bytes=1_000)
    assert data_uri is None
    assert "KB or smaller" in error


def test_branding_is_ignored_without_the_entitlement() -> None:
    brand = build_branding(
        white_label_allowed=False,
        branding={"company_name": "Evil Co", "brand_color": "#ff0000"},
        organization_name="Acme",
    )
    assert brand["name"] == "Zentra"
    assert brand["prepared_by"] == "Zentra"
    assert brand["color"] is None


def test_branding_applies_with_the_entitlement() -> None:
    brand = build_branding(
        white_label_allowed=True,
        branding={"company_name": "Acme Advisory", "brand_color": "#123456"},
        organization_name="Acme",
    )
    assert brand["name"] == "Acme Advisory"
    assert brand["color"] == "#123456"
    assert "Zentra" in brand["prepared_by"]


def test_branding_rejects_a_remote_logo_url() -> None:
    """A stored logo must be an inline data URI; a URL would be an SSRF vector."""
    brand = build_branding(
        white_label_allowed=True,
        branding={"logo_data_uri": "https://evil.example/logo.png"},
        organization_name="Acme",
    )
    assert brand["logo_data_uri"] is None


# ------------------------------------------------------------------ rendering
def test_pdf_renders_and_is_a_real_pdf() -> None:
    pdf = render_pdf(_minimal_context())
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 3000


def test_pdf_contains_the_required_disclaimer() -> None:
    import re

    from zentra.reports.pdf import render_html

    html = render_html(_minimal_context())
    flat = re.sub(r"\s+", " ", html)
    assert "informational assessments based on" in flat
    assert "not be interpreted as legal, regulatory, audit or certification advice" in flat
    assert "does not itself confer, demonstrate or guarantee compliance" in flat
    # It must never claim to deliver a certification.
    for claim in ["ISO 27001 compliant", "SOC 2 compliant", "guarantees compliance"]:
        assert claim not in html


def test_pdf_escapes_injected_markup_in_customer_data() -> None:
    from zentra.reports.pdf import render_html

    context = _minimal_context()
    context["vendors"][0]["name"] = "<script>alert('xss')</script>"
    context["organization"]["name"] = "</style><script>bad()</script>"
    html = render_html(context)
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;" in html


def test_pdf_renders_with_no_vendors() -> None:
    pdf = render_pdf(
        _minimal_context(
            vendors=[],
            summary={
                "total_vendors": 0,
                "critical_vendors": 0,
                "high_risk_vendors": 0,
                "average_score": None,
                "open_findings": 0,
                "vendors_needing_attention": 0,
            },
        )
    )
    assert pdf.startswith(b"%PDF")


def test_pdf_renders_an_unscored_vendor() -> None:
    context = _minimal_context(unscored_vendors=1)
    context["vendors"][0].update(
        {"score": None, "risk_level": None, "breakdown": None, "findings": [], "key_findings": []}
    )
    from zentra.reports.pdf import render_html

    html = render_html(context)
    assert "Not Assessed" in html
    assert render_pdf(context).startswith(b"%PDF")


# --------------------------------------------------------------------- service
def test_report_lifecycle_through_the_api(account: Account, db, grant_plan) -> None:
    from zentra.services import reports as reports_service

    grant_plan(account.organization_id, "growth")
    account.post("/api/v1/vendors", json={"name": "Vendor", "domain": "report-vendor.io"})

    queued = account.post("/api/v1/reports", json={"title": "Q3 register"})
    assert queued.status_code == 202
    report_id = queued.json()["id"]
    assert queued.json()["status"] == "queued"
    assert queued.json()["download_url"] is None

    reports_service.render_report(db, report_id=uuid.UUID(report_id))
    db.commit()

    ready = account.get(f"/api/v1/reports/{report_id}").json()
    assert ready["status"] == "completed"
    assert ready["file_size"] > 0

    download = account.get(f"/api/v1/reports/{report_id}/download")
    assert download.status_code == 200
    assert download.headers["content-disposition"].startswith("attachment;")
    assert download.headers["cache-control"] == "private, no-store"


def test_report_generation_is_idempotent(account: Account, db, grant_plan) -> None:
    grant_plan(account.organization_id, "growth")
    first = account.post("/api/v1/reports", json={"idempotency_key": "same-key-1"}).json()
    second = account.post("/api/v1/reports", json={"idempotency_key": "same-key-1"}).json()
    assert first["id"] == second["id"]


def test_downloading_an_unfinished_report_is_a_clear_error(account: Account, grant_plan) -> None:
    grant_plan(account.organization_id, "growth")
    report_id = account.post("/api/v1/reports", json={}).json()["id"]
    response = account.get(f"/api/v1/reports/{report_id}/download")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "REPORT_NOT_READY"


def test_report_render_failure_is_recorded_not_raised(
    account: Account, db, grant_plan, monkeypatch
) -> None:
    from zentra.services import reports as reports_service

    grant_plan(account.organization_id, "growth")
    report_id = account.post("/api/v1/reports", json={}).json()["id"]

    monkeypatch.setattr(
        reports_service, "render_pdf", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    report = reports_service.render_report(db, report_id=uuid.UUID(report_id))
    db.commit()

    assert report.status == "failed"
    assert "boom" not in (report.error_message or "")
    body = account.get(f"/api/v1/reports/{report_id}").json()
    assert body["status"] == "failed"
    assert body["error_message"]


def test_report_download_is_confined_to_the_storage_directory(
    account: Account, db, grant_plan
) -> None:
    from zentra.db.models import ReportExport
    from zentra.errors import NotFoundError
    from zentra.services import reports as reports_service

    grant_plan(account.organization_id, "growth")
    report_id = account.post("/api/v1/reports", json={}).json()["id"]
    reports_service.render_report(db, report_id=uuid.UUID(report_id))
    db.commit()

    export = db.query(ReportExport).filter(ReportExport.report_id == uuid.UUID(report_id)).one()
    export.file_path = "/etc/passwd"
    db.commit()

    with pytest.raises(NotFoundError):
        reports_service.read_export(db, export=export)


def test_pdf_renderer_blocks_external_resources() -> None:
    """The report renderer must never fetch a remote resource.

    Autoescaping already stops a vendor name injecting markup, but that is one
    template change away from being untrue. This asserts the second control:
    anything that is not an inline data URI is refused outright.
    """
    from zentra.reports.pdf import ReportResourceBlocked, _inline_only_url_fetcher

    for blocked in (
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://127.0.0.1:8000/api/v1/me",
        "https://example.com/logo.png",
        "file:///etc/passwd",
    ):
        with pytest.raises(ReportResourceBlocked):
            _inline_only_url_fetcher(blocked)


def test_pdf_renderer_allows_inline_data_uri() -> None:
    """A validated inline logo must still render, or the block would break reports."""
    from zentra.reports.pdf import _inline_only_url_fetcher

    # 1x1 transparent GIF.
    gif = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
    assert _inline_only_url_fetcher(gif).read()[:4] == b"GIF8"
