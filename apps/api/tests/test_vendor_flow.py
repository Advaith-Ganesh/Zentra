"""The core product loop, end to end.

sign up → add vendor → scan → score → findings → recommended action → PDF →
dashboard → history.
"""

from __future__ import annotations

import uuid

from tests.conftest import Account


def _run_queued_scan(db, vendor_id: str):
    """Execute the vendor's queued scan the way the Celery worker would."""
    from zentra.db.models import Scan
    from zentra.services import scans as scans_service

    scan = (
        db.query(Scan)
        .filter(Scan.vendor_id == uuid.UUID(vendor_id), Scan.status == "queued")
        .order_by(Scan.created_at.desc())
        .first()
    )
    assert scan is not None, "adding a vendor must queue an initial scan"
    result = scans_service.execute_scan(db, scan.id)
    db.commit()
    return result


def test_full_vendor_lifecycle(account: Account, db, grant_plan) -> None:
    grant_plan(account.organization_id, "growth")

    # 1. Add a vendor -------------------------------------------------------
    created = account.post(
        "/api/v1/vendors",
        json={
            "name": "Acme Payments",
            "domain": "acme-payments.io",
            "category": "Payments",
            "criticality": "critical",
            "description": "Card processing partner.",
        },
    )
    assert created.status_code == 201
    vendor = created.json()
    vendor_id = vendor["id"]
    assert vendor["domain"] == "acme-payments.io"
    assert vendor["current_score"] is None

    # 2. The initial scan is queued, not run inline -------------------------
    scans = account.get(f"/api/v1/vendors/{vendor_id}/scans").json()
    assert len(scans) == 1
    assert scans[0]["trigger"] == "initial"
    assert scans[0]["status"] == "queued"

    # 3. The worker runs it -------------------------------------------------
    scan = _run_queued_scan(db, vendor_id)
    assert scan.status in ("completed", "partial")

    # 4. The score is available and explainable -----------------------------
    score = account.get(f"/api/v1/vendors/{vendor_id}/score").json()
    assert score["score"] is not None
    assert score["risk_level"] in ("low", "medium", "high", "critical")
    assert score["breakdown"]["categories"]
    assert sum(c["max_points"] for c in score["breakdown"]["categories"]) == 100
    verdict = score["verdict"]
    assert verdict["headline"] and verdict["explanation"] and verdict["recommended_action"]
    assert any("not legal, regulatory" in d for d in verdict["disclaimers"])

    # 5. Normalized results carry provenance --------------------------------
    detail = account.get(f"/api/v1/scans/{scan.id}").json()
    assert detail["results"]
    for result in detail["results"]:
        assert result["source"]
        assert result["checked_at"]
        assert 0.0 <= result["confidence"] <= 1.0
        assert result["status"] in ("pass", "warn", "fail", "unknown", "error")

    # 6. Findings exist for every problem, with a recommendation ------------
    findings = account.get(f"/api/v1/vendors/{vendor_id}/findings").json()
    for finding in findings:
        assert finding["recommendation"]
        assert finding["status"] == "open"
        assert finding["source"]

    # 7. The dashboard reflects the scan ------------------------------------
    dashboard = account.get("/api/v1/dashboard").json()
    assert dashboard["summary"]["total_vendors"] == 1
    assert dashboard["recent_scans"]
    assert dashboard["entitlements"]["plan"] == "growth"

    # 8. A PDF report can be generated and downloaded -----------------------
    from zentra.services import reports as reports_service

    report_id = account.post("/api/v1/reports", json={}).json()["id"]
    reports_service.render_report(db, report_id=uuid.UUID(report_id))
    db.commit()

    status = account.get(f"/api/v1/reports/{report_id}").json()
    assert status["status"] == "completed"
    assert status["download_url"]

    download = account.get(f"/api/v1/reports/{report_id}/download")
    assert download.status_code == 200
    assert download.headers["content-type"] == "application/pdf"
    assert download.content.startswith(b"%PDF")
    assert len(download.content) > 5000

    # 9. Historical scans accumulate ----------------------------------------
    account.post(f"/api/v1/vendors/{vendor_id}/scan", json={})
    _run_queued_scan(db, vendor_id)
    history = account.get(f"/api/v1/vendors/{vendor_id}/score").json()["history"]
    assert len(history) >= 2
    assert all(point["score"] is not None for point in history)


def test_scan_status_transitions_queued_then_terminal(account: Account, db) -> None:
    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Vendor", "domain": "vendor-status.io"}
    ).json()["id"]

    queued = account.get(f"/api/v1/vendors/{vendor_id}/scans").json()[0]
    assert queued["status"] == "queued"
    assert queued["completed_at"] is None

    scan = _run_queued_scan(db, vendor_id)
    finished = account.get(f"/api/v1/scans/{scan.id}").json()
    assert finished["status"] in ("completed", "partial")
    assert finished["completed_at"] is not None
    assert finished["checks_total"] > 0


def test_duplicate_scan_requests_reuse_the_in_flight_scan(account: Account) -> None:
    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Vendor", "domain": "dedupe-vendor.io"}
    ).json()["id"]
    first = account.post(f"/api/v1/vendors/{vendor_id}/scan", json={}).json()
    second = account.post(f"/api/v1/vendors/{vendor_id}/scan", json={}).json()
    assert first["id"] == second["id"]
    assert len(account.get(f"/api/v1/vendors/{vendor_id}/scans").json()) == 1


def test_scan_is_idempotent_on_repeated_execution(account: Account, db) -> None:
    """A redelivered Celery message must not double-write results."""
    from zentra.db.models import ScanResult
    from zentra.services import scans as scans_service

    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Vendor", "domain": "idempotent-vendor.io"}
    ).json()["id"]
    scan = _run_queued_scan(db, vendor_id)
    before = db.query(ScanResult).filter(ScanResult.scan_id == scan.id).count()

    scans_service.execute_scan(db, scan.id)
    db.commit()
    after = db.query(ScanResult).filter(ScanResult.scan_id == scan.id).count()
    assert before == after


def test_findings_resolve_when_they_stop_appearing(account: Account, db) -> None:
    from zentra.db.models import Finding, Scan, Vendor
    from zentra.services import findings as findings_service

    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Vendor", "domain": "resolving-vendor.io"}
    ).json()["id"]
    scan = _run_queued_scan(db, vendor_id)

    vendor = db.get(Vendor, uuid.UUID(vendor_id))
    open_before = (
        db.query(Finding).filter(Finding.vendor_id == vendor.id, Finding.status == "open").count()
    )
    if open_before == 0:
        return

    # A later scan with no problems must auto-resolve them.
    findings_service.sync_findings(db, vendor=vendor, scan=db.get(Scan, scan.id), results=[])
    db.commit()
    open_after = (
        db.query(Finding).filter(Finding.vendor_id == vendor.id, Finding.status == "open").count()
    )
    assert open_after == 0


def test_remediation_status_changes_are_recorded_with_history(
    account: Account, db, grant_plan
) -> None:
    grant_plan(account.organization_id, "growth")
    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Vendor", "domain": "remediation-vendor.io"}
    ).json()["id"]
    _run_queued_scan(db, vendor_id)

    findings = account.get(f"/api/v1/vendors/{vendor_id}/findings").json()
    if not findings:
        return
    finding_id = findings[0]["id"]

    updated = account.patch(
        f"/api/v1/findings/{finding_id}",
        json={"status": "in_progress", "note": "Raised with the vendor on 1 September."},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "in_progress"

    accepted = account.patch(
        f"/api/v1/findings/{finding_id}",
        json={"status": "accepted_risk", "note": "Signed off by the CTO."},
    )
    assert accepted.json()["status"] == "accepted_risk"
    assert accepted.json()["resolved_at"] is not None

    history = account.get(f"/api/v1/findings/{finding_id}/history").json()
    assert len(history) >= 2
    transitions = {(h["from_status"], h["to_status"]) for h in history}
    assert ("open", "in_progress") in transitions
    assert ("in_progress", "accepted_risk") in transitions


def test_invalid_finding_status_is_rejected(account: Account, db, grant_plan) -> None:
    grant_plan(account.organization_id, "growth")
    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Vendor", "domain": "status-vendor.io"}
    ).json()["id"]
    _run_queued_scan(db, vendor_id)
    findings = account.get(f"/api/v1/vendors/{vendor_id}/findings").json()
    if not findings:
        return
    response = account.patch(
        f"/api/v1/findings/{findings[0]['id']}", json={"status": "ignored_forever"}
    )
    assert response.status_code == 422


def test_score_increase_raises_an_alert(account: Account, db) -> None:
    """A material worsening must produce an alert with the score delta."""
    from zentra.db.models import Scan, Vendor
    from zentra.services import alerts as alerts_service

    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Vendor", "domain": "alerting-vendor.io"}
    ).json()["id"]
    scan = _run_queued_scan(db, vendor_id)

    vendor = db.get(Vendor, uuid.UUID(vendor_id))
    alert = alerts_service.evaluate_score_change(
        db,
        vendor=vendor,
        scan=db.get(Scan, scan.id),
        old_score=20,
        new_score=45,
    )
    db.commit()
    assert alert is not None
    assert alert.score_delta == 25
    assert alert.old_score == 20 and alert.new_score == 45

    listed = account.get("/api/v1/alerts").json()
    assert any(a["id"] == str(alert.id) for a in listed)


def test_small_score_movement_does_not_alert(account: Account, db) -> None:
    from zentra.db.models import Scan, Vendor
    from zentra.services import alerts as alerts_service

    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Vendor", "domain": "quiet-vendor.io"}
    ).json()["id"]
    scan = _run_queued_scan(db, vendor_id)
    vendor = db.get(Vendor, uuid.UUID(vendor_id))

    alert = alerts_service.evaluate_score_change(
        db, vendor=vendor, scan=db.get(Scan, scan.id), old_score=20, new_score=25
    )
    assert alert is None


def test_alerts_are_deduplicated_per_scan(account: Account, db) -> None:
    from zentra.db.models import Scan, Vendor
    from zentra.services import alerts as alerts_service

    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Vendor", "domain": "dupe-alert-vendor.io"}
    ).json()["id"]
    scan = _run_queued_scan(db, vendor_id)
    vendor = db.get(Vendor, uuid.UUID(vendor_id))

    first = alerts_service.evaluate_score_change(
        db, vendor=vendor, scan=db.get(Scan, scan.id), old_score=10, new_score=60
    )
    db.commit()
    second = alerts_service.evaluate_score_change(
        db, vendor=vendor, scan=db.get(Scan, scan.id), old_score=10, new_score=60
    )
    assert first is not None
    assert second is None


def test_vendor_search_filter_and_sort(account: Account) -> None:
    for name, domain in [("Stripe", "stripe.com"), ("Slack", "slack.com"), ("Notion", "notion.so")]:
        account.post("/api/v1/vendors", json={"name": name, "domain": domain})

    assert account.get("/api/v1/vendors?search=str").json()["total"] == 1
    assert account.get("/api/v1/vendors?search=nomatch").json()["total"] == 0
    by_name = account.get("/api/v1/vendors?sort=name&direction=asc").json()["items"]
    assert [v["name"] for v in by_name] == ["Notion", "Slack", "Stripe"]

    paged = account.get("/api/v1/vendors?limit=2&offset=0").json()
    assert len(paged["items"]) == 2
    assert paged["total"] == 3


def test_archived_vendors_are_hidden_by_default(account: Account) -> None:
    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Old Vendor", "domain": "old-vendor.io"}
    ).json()["id"]
    account.post(f"/api/v1/vendors/{vendor_id}/archive")

    assert account.get("/api/v1/vendors").json()["total"] == 0
    assert account.get("/api/v1/vendors?status=archived").json()["total"] == 1
    assert account.get("/api/v1/vendors?status=all").json()["total"] == 1


def test_invalid_vendor_domain_is_rejected_with_a_clear_error(account: Account) -> None:
    for domain in ["localhost", "127.0.0.1", "not a domain", "169.254.169.254", "x.local"]:
        response = account.post("/api/v1/vendors", json={"name": "Bad", "domain": domain})
        assert response.status_code == 422, domain
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_oversized_input_is_rejected(account: Account) -> None:
    response = account.post("/api/v1/vendors", json={"name": "A" * 5000, "domain": "example.com"})
    assert response.status_code == 422


def test_sql_injection_payloads_are_handled_as_data(account: Account) -> None:
    """Parameterized queries mean these are values, never syntax."""
    account.post("/api/v1/vendors", json={"name": "Stripe", "domain": "stripe.com"})
    for payload in [
        "'; DROP TABLE vendors; --",
        "' OR '1'='1",
        "1; DELETE FROM vendors WHERE 1=1;--",
        "%' UNION SELECT * FROM users --",
    ]:
        response = account.get("/api/v1/vendors", params={"search": payload})
        assert response.status_code == 200
        assert response.json()["total"] == 0
    # The table is still there and still holds the vendor.
    assert account.get("/api/v1/vendors").json()["total"] == 1


def test_xss_payload_is_stored_and_returned_as_data_not_markup(account: Account) -> None:
    payload = "<script>alert('xss')</script>"
    created = account.post(
        "/api/v1/vendors",
        json={"name": payload, "domain": "xss-vendor.io", "description": payload},
    )
    assert created.status_code == 201
    # The API returns JSON, so the payload round-trips as an inert string.
    assert created.json()["name"] == payload
    assert created.headers["content-type"].startswith("application/json")
    assert created.headers["X-Content-Type-Options"] == "nosniff"
