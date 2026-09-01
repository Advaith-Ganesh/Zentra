"""Cross-tenant access control.

Two organizations exist. Every resource one of them owns must be completely
invisible and immutable to the other, through every route that accepts an
identifier.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from tests.conftest import Account


@pytest.fixture
def acme_with_data(account: Account, db) -> dict:
    """Acme owns a vendor, a completed scan, findings and a report."""
    from zentra.db.models import Finding, Report, Scan, Vendor
    from zentra.services import scans as scans_service

    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Stripe", "domain": "stripe.com"}
    ).json()["id"]

    vendor = db.get(Vendor, uuid.UUID(vendor_id))
    scan = scans_service.execute_scan(
        db, db.query(Scan).filter(Scan.vendor_id == vendor.id).one().id
    )
    db.commit()

    finding = db.query(Finding).filter(Finding.vendor_id == vendor.id).first()
    report = Report(
        organization_id=account.organization_id,
        kind="vendor_risk_register",
        title="Acme register",
        status="completed",
    )
    db.add(report)
    db.commit()

    return {
        "vendor_id": vendor_id,
        "scan_id": str(scan.id),
        "finding_id": str(finding.id) if finding else None,
        "report_id": str(report.id),
        "organization_id": str(account.organization_id),
    }


# ------------------------------------------------------------------- reads
def test_vendor_list_is_scoped_to_the_callers_organization(
    account: Account, other_account: Account
) -> None:
    account.post("/api/v1/vendors", json={"name": "Stripe", "domain": "stripe.com"})
    other_account.post("/api/v1/vendors", json={"name": "Slack", "domain": "slack.com"})

    mine = account.get("/api/v1/vendors").json()
    theirs = other_account.get("/api/v1/vendors").json()

    assert [v["domain"] for v in mine["items"]] == ["stripe.com"]
    assert [v["domain"] for v in theirs["items"]] == ["slack.com"]
    assert mine["total"] == theirs["total"] == 1


def test_cannot_read_another_organizations_vendor(
    acme_with_data: dict, other_account: Account
) -> None:
    response = other_account.get(f"/api/v1/vendors/{acme_with_data['vendor_id']}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "VENDOR_NOT_FOUND"


def test_cannot_read_another_organizations_scan(
    acme_with_data: dict, other_account: Account
) -> None:
    response = other_account.get(f"/api/v1/scans/{acme_with_data['scan_id']}")
    assert response.status_code == 404


def test_cannot_read_another_organizations_vendor_score_or_scans(
    acme_with_data: dict, other_account: Account
) -> None:
    vendor_id = acme_with_data["vendor_id"]
    for path in [
        f"/api/v1/vendors/{vendor_id}/score",
        f"/api/v1/vendors/{vendor_id}/scans",
        f"/api/v1/vendors/{vendor_id}/findings",
    ]:
        assert other_account.get(path).status_code == 404, path


def test_cannot_read_another_organizations_report(
    acme_with_data: dict, other_account: Account
) -> None:
    for path in [
        f"/api/v1/reports/{acme_with_data['report_id']}",
        f"/api/v1/reports/{acme_with_data['report_id']}/download",
    ]:
        assert other_account.get(path).status_code == 404, path


def test_findings_list_does_not_leak_across_organizations(
    acme_with_data: dict, other_account: Account
) -> None:
    findings = other_account.get("/api/v1/findings").json()
    assert findings == []


def test_dashboard_counters_are_per_organization(
    acme_with_data: dict, other_account: Account
) -> None:
    theirs = other_account.get("/api/v1/dashboard").json()
    assert theirs["summary"]["total_vendors"] == 0
    assert theirs["recent_scans"] == []
    assert theirs["recent_alerts"] == []


def test_alerts_are_per_organization(acme_with_data: dict, other_account: Account) -> None:
    assert other_account.get("/api/v1/alerts").json() == []


# ------------------------------------------------------------------- writes
def test_cannot_modify_another_organizations_vendor(
    acme_with_data: dict, other_account: Account
) -> None:
    vendor_id = acme_with_data["vendor_id"]
    assert (
        other_account.patch(f"/api/v1/vendors/{vendor_id}", json={"name": "Hijacked"}).status_code
        == 404
    )
    assert other_account.delete(f"/api/v1/vendors/{vendor_id}").status_code == 404
    assert other_account.post(f"/api/v1/vendors/{vendor_id}/archive").status_code == 404


def test_cannot_trigger_a_scan_on_another_organizations_vendor(
    acme_with_data: dict, other_account: Account
) -> None:
    response = other_account.post(f"/api/v1/vendors/{acme_with_data['vendor_id']}/scan", json={})
    assert response.status_code == 404


def test_cannot_modify_another_organizations_finding(
    acme_with_data: dict, other_account: Account, grant_plan
) -> None:
    if not acme_with_data["finding_id"]:
        pytest.skip("the scan produced no findings for this fixture domain")
    grant_plan(other_account.organization_id, "growth")
    response = other_account.patch(
        f"/api/v1/findings/{acme_with_data['finding_id']}",
        json={"status": "accepted_risk"},
    )
    assert response.status_code == 404


def test_same_domain_can_be_tracked_by_both_organizations(
    account: Account, other_account: Account
) -> None:
    """Uniqueness is per organization, not global."""
    first = account.post("/api/v1/vendors", json={"name": "Stripe", "domain": "stripe.com"})
    second = other_account.post("/api/v1/vendors", json={"name": "Stripe", "domain": "stripe.com"})
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] != second.json()["id"]


def test_duplicate_domain_within_one_organization_is_rejected(account: Account) -> None:
    account.post("/api/v1/vendors", json={"name": "Stripe", "domain": "stripe.com"})
    duplicate = account.post(
        "/api/v1/vendors", json={"name": "Stripe Again", "domain": "STRIPE.com"}
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "VENDOR_ALREADY_EXISTS"


# --------------------------------------------------- organization header spoofing
def test_organization_header_cannot_be_used_to_switch_tenants(
    acme_with_data: dict, other_account: Account
) -> None:
    response = other_account.client.get(
        "/api/v1/vendors",
        headers={
            **other_account.headers,
            "X-Zentra-Organization": acme_with_data["organization_id"],
        },
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "PERMISSION_DENIED"


def test_unknown_organization_header_is_rejected(other_account: Account) -> None:
    response = other_account.client.get(
        "/api/v1/vendors",
        headers={**other_account.headers, "X-Zentra-Organization": str(uuid.uuid4())},
    )
    assert response.status_code == 403


def test_malformed_organization_header_is_rejected(other_account: Account) -> None:
    response = other_account.client.get(
        "/api/v1/vendors",
        headers={**other_account.headers, "X-Zentra-Organization": "not-a-uuid"},
    )
    assert response.status_code == 403


def test_members_and_billing_are_not_shared(
    acme_with_data: dict, other_account: Account, account: Account
) -> None:
    theirs = other_account.get("/api/v1/organization/members").json()
    assert [m["email"] for m in theirs] == [other_account.email]
    assert other_account.get("/api/v1/organization").json()["id"] == str(
        other_account.organization_id
    )


def test_api_key_is_bound_to_its_own_organization(
    client: TestClient, account: Account, other_account: Account, grant_plan
) -> None:
    grant_plan(account.organization_id, "scale")
    account.post("/api/v1/vendors", json={"name": "Stripe", "domain": "stripe.com"})
    secret = account.post("/api/v1/api-keys", json={"name": "CI"}).json()["secret"]

    other_account.post("/api/v1/vendors", json={"name": "Slack", "domain": "slack.com"})

    response = client.get("/api/v1/public/vendors", headers={"X-API-Key": secret})
    assert response.status_code == 200
    assert [v["domain"] for v in response.json()["items"]] == ["stripe.com"]
