"""Background tasks, benchmarking and the internal admin surface."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from tests.conftest import Account, signup


# --------------------------------------------------------------- worker tasks
def _vendor_and_scan(account: Account, db, domain: str):
    from zentra.db.models import Scan, Vendor

    vendor_id = account.post("/api/v1/vendors", json={"name": "Vendor", "domain": domain}).json()[
        "id"
    ]
    vendor = db.get(Vendor, uuid.UUID(vendor_id))
    scan = db.query(Scan).filter(Scan.vendor_id == vendor.id).one()
    return vendor, scan


def test_run_scan_task_executes_a_queued_scan(account: Account, db) -> None:
    from zentra.workers.tasks import run_scan_task

    _, scan = _vendor_and_scan(account, db, "task-vendor.io")
    db.commit()

    result = run_scan_task(str(scan.id))
    assert result["status"] in ("completed", "partial")
    assert result["scan_id"] == str(scan.id)

    db.expire_all()
    from zentra.db.models import Scan

    assert db.get(Scan, scan.id).completed_at is not None


def test_run_scan_task_ignores_a_malformed_id() -> None:
    from zentra.workers.tasks import run_scan_task

    assert run_scan_task("not-a-uuid")["status"] == "invalid_scan_id"


def test_run_scan_task_is_safe_to_redeliver(account: Account, db) -> None:
    """Celery delivers at-least-once; a repeat must not double-write."""
    from zentra.db.models import ScanResult
    from zentra.workers.tasks import run_scan_task

    _, scan = _vendor_and_scan(account, db, "redelivered-vendor.io")
    db.commit()

    run_scan_task(str(scan.id))
    first = db.query(ScanResult).filter(ScanResult.scan_id == scan.id).count()
    run_scan_task(str(scan.id))
    assert db.query(ScanResult).filter(ScanResult.scan_id == scan.id).count() == first


def test_rescan_sweep_queues_due_vendors_and_moves_their_schedule(account: Account, db) -> None:
    from zentra.db.models import Scan, Vendor
    from zentra.workers.tasks import rescan_due_vendors

    vendor, scan = _vendor_and_scan(account, db, "due-vendor.io")
    # Finish the initial scan, then make the vendor due for a rescan.
    from zentra.services import scans as scans_service

    scans_service.execute_scan(db, scan.id)
    vendor.next_scan_at = datetime.now(UTC) - timedelta(hours=1)
    db.commit()

    result = rescan_due_vendors()
    assert result["queued"] >= 1

    db.expire_all()
    scans = db.query(Scan).filter(Scan.vendor_id == vendor.id).all()
    assert any(s.trigger == "scheduled" for s in scans)
    # The schedule must move immediately so the next sweep does not re-queue it.
    assert db.get(Vendor, vendor.id).next_scan_at > datetime.now(UTC)


def test_rescan_sweep_skips_a_vendor_with_a_scan_already_in_flight(account: Account, db) -> None:
    from zentra.db.models import Scan
    from zentra.workers.tasks import rescan_due_vendors

    vendor, _ = _vendor_and_scan(account, db, "inflight-vendor.io")
    vendor.next_scan_at = datetime.now(UTC) - timedelta(hours=1)
    db.commit()

    rescan_due_vendors()
    db.expire_all()
    # The queued initial scan is still the only one.
    assert db.query(Scan).filter(Scan.vendor_id == vendor.id).count() == 1


def test_reap_stuck_scans_fails_a_scan_whose_worker_died(account: Account, db) -> None:
    from zentra.db.models import Scan
    from zentra.workers.tasks import reap_stuck_scans

    _, scan = _vendor_and_scan(account, db, "stuck-worker-vendor.io")
    scan.status = "running"
    scan.started_at = datetime.now(UTC) - timedelta(hours=3)
    db.commit()

    assert reap_stuck_scans()["reaped"] >= 1
    db.expire_all()
    reaped = db.get(Scan, scan.id)
    assert reaped.status == "failed"
    assert reaped.error_code == "WORKER_LOST"
    # The customer-facing message says what happens next, not what broke.
    assert "retry" in (reaped.error_message or "").lower()


def test_reap_leaves_a_recently_started_scan_alone(account: Account, db) -> None:
    from zentra.db.models import Scan
    from zentra.workers.tasks import reap_stuck_scans

    _, scan = _vendor_and_scan(account, db, "recent-scan-vendor.io")
    scan.status = "running"
    scan.started_at = datetime.now(UTC)
    db.commit()

    reap_stuck_scans()
    db.expire_all()
    assert db.get(Scan, scan.id).status == "running"


def test_generate_report_task_produces_a_pdf(account: Account, db, grant_plan) -> None:
    from zentra.db.models import ReportExport
    from zentra.workers.tasks import generate_report_task

    grant_plan(account.organization_id, "growth")
    account.post("/api/v1/vendors", json={"name": "V", "domain": "report-task-vendor.io"})
    report_id = account.post("/api/v1/reports", json={}).json()["id"]

    assert generate_report_task(report_id)["status"] == "completed"
    export = db.query(ReportExport).filter(ReportExport.report_id == uuid.UUID(report_id)).one()
    assert export.file_size > 0
    assert export.checksum


def test_purge_expired_data_removes_old_anonymous_scans(db) -> None:
    from zentra.db.models import PublicScan
    from zentra.workers.tasks import purge_expired_data

    old = PublicScan(domain="old-public-scan.io", score=5, risk_level="low")
    recent = PublicScan(domain="recent-public-scan.io", score=5, risk_level="low")
    db.add_all([old, recent])
    db.flush()
    old.created_at = datetime.now(UTC) - timedelta(days=60)
    db.commit()

    result = purge_expired_data()
    assert result["public_scans"] >= 1

    db.expire_all()
    remaining = {row.domain for row in db.query(PublicScan).all()}
    assert "old-public-scan.io" not in remaining
    assert "recent-public-scan.io" in remaining


def test_weekly_summary_only_goes_to_plans_that_include_alerts(
    account: Account, db, grant_plan
) -> None:
    from zentra.integrations.email.provider import ConsoleEmailProvider
    from zentra.workers.tasks import send_weekly_summaries

    account.post("/api/v1/vendors", json={"name": "V", "domain": "summary-vendor.io"})
    db.commit()

    # Free plan: no alerts entitlement, so no summary.
    ConsoleEmailProvider.clear()
    send_weekly_summaries()
    assert not any("weekly" in m.subject.lower() for m in ConsoleEmailProvider.outbox)

    grant_plan(account.organization_id, "growth")
    ConsoleEmailProvider.clear()
    assert send_weekly_summaries()["sent"] >= 1
    assert any("weekly" in m.subject.lower() for m in ConsoleEmailProvider.outbox)


def test_dispatch_is_disabled_in_the_test_environment(account: Account, db) -> None:
    """Tests drive the worker explicitly; automatic dispatch would leak work."""
    from zentra.workers.dispatch import dispatch_scan

    _, scan = _vendor_and_scan(account, db, "dispatch-vendor.io")
    db.commit()
    assert dispatch_scan(scan.id) is None


# ---------------------------------------------------------------- benchmarking
def _org(db, account: Account):
    from zentra.db.models import Organization

    return db.get(Organization, account.organization_id)


def test_benchmark_is_withheld_until_the_cohort_is_large_enough(account: Account, db) -> None:
    from zentra.services import benchmark as benchmark_service

    benchmark_service.recompute(db)
    db.commit()

    result = benchmark_service.for_organization(db, _org(db, account))
    assert result["available"] is False
    assert result["sample_size"] == 0
    # It must not invent a cohort it does not have.
    assert "not yet enough" in result["message"]


def test_benchmark_appears_once_the_cohort_is_large_enough(
    client: TestClient, db, grant_plan
) -> None:
    from zentra.db.models import Vendor
    from zentra.services import benchmark as benchmark_service

    accounts = []
    for index in range(6):
        member = signup(client, email=f"bench{index}@cohort.io", org=f"Cohort {index}")
        accounts.append(member)
        member.post("/api/v1/vendors", json={"name": "V", "domain": f"bench{index}.io"})

    db.commit()
    # Give every vendor a score so the cohort has data to aggregate.
    for index, vendor in enumerate(db.query(Vendor).all()):
        vendor.current_score = 10 + index * 5
        vendor.current_risk_level = "low"
    db.commit()

    stored = benchmark_service.recompute(db)
    db.commit()
    assert stored >= 1

    grant_plan(accounts[0].organization_id, "growth")
    result = accounts[0].get("/api/v1/benchmark").json()
    assert result["available"] is True
    assert result["sample_size"] >= 5
    # The reported sample size is the real one.
    assert str(result["sample_size"]) in result["message"]
    assert result["cohort_median"] is not None


def test_benchmark_excludes_organizations_that_opted_out(client: TestClient, db) -> None:
    from zentra.db.models import Organization, Vendor
    from zentra.services import benchmark as benchmark_service

    for index in range(6):
        member = signup(client, email=f"optout{index}@cohort.io", org=f"OptOut {index}")
        member.post("/api/v1/vendors", json={"name": "V", "domain": f"optout{index}.io"})
    db.commit()
    for vendor in db.query(Vendor).all():
        vendor.current_score = 20
    for organization in db.query(Organization).all():
        organization.benchmark_opt_in = False
    db.commit()

    benchmark_service.recompute(db)
    db.commit()

    from zentra.db.models import BenchmarkData

    assert db.query(BenchmarkData).count() == 0


def test_benchmark_requires_the_entitlement(account: Account) -> None:
    assert account.get("/api/v1/benchmark").status_code == 402


# ----------------------------------------------------------------------- admin
@pytest.fixture
def platform_admin(client: TestClient, db) -> Account:
    from zentra.db.models import User

    admin = signup(client, email="ops@zentra-internal.io", org="Zentra Ops")
    user = db.get(User, admin.user_id)
    # Only ever set server-side from ZENTRA_ADMIN_EMAILS in a real deployment.
    user.is_platform_admin = True
    db.commit()
    return admin


def test_admin_overview_reports_system_state(platform_admin: Account) -> None:
    body = platform_admin.get("/api/v1/admin/overview").json()
    assert body["environment"] == "test"
    assert body["mock_scanners"] is True
    assert set(body["totals"]) == {"users", "organizations", "vendors", "scans"}
    assert body["dependencies"]["database"] == "ok"
    assert "benchmarking" in body["feature_flags"]


def test_admin_scan_health_and_queue(platform_admin: Account, db) -> None:
    from zentra.services import scans as scans_service

    _, scan = _vendor_and_scan(platform_admin, db, "admin-health-vendor.io")
    scans_service.execute_scan(db, scan.id)
    db.commit()

    health = platform_admin.get("/api/v1/admin/scan-health").json()
    assert health["window_hours"] == 24
    assert sum(health["by_status"].values()) >= 1

    queue = platform_admin.get("/api/v1/admin/queue").json()
    assert "database" in queue and "broker_queue_depth" in queue


def test_admin_lists_organizations_and_audit(platform_admin: Account) -> None:
    organizations = platform_admin.get("/api/v1/admin/organizations").json()
    assert any(o["name"] == "Zentra Ops" for o in organizations)

    audit = platform_admin.get("/api/v1/admin/audit").json()
    assert any(entry["action"] == "organization.created" for entry in audit)

    usage = platform_admin.get("/api/v1/admin/api-usage").json()
    assert set(usage) == {"active_keys", "used_last_7_days"}


def test_admin_is_invisible_without_the_server_side_flag(account: Account) -> None:
    for path in [
        "/api/v1/admin/overview",
        "/api/v1/admin/organizations",
        "/api/v1/admin/scan-health",
        "/api/v1/admin/queue",
        "/api/v1/admin/webhooks",
        "/api/v1/admin/audit",
        "/api/v1/admin/api-usage",
    ]:
        response = account.get(path)
        assert response.status_code == 404, path


def test_admin_is_unreachable_with_an_api_key(
    client: TestClient, platform_admin: Account, grant_plan
) -> None:
    """A machine credential must never satisfy the admin gate."""
    grant_plan(platform_admin.organization_id, "scale")
    secret = platform_admin.post("/api/v1/api-keys", json={"name": "CI"}).json()["secret"]
    response = client.get("/api/v1/admin/overview", headers={"X-API-Key": secret})
    assert response.status_code == 404


def test_rescan_sweep_survives_a_dead_broker(account: Account, db, monkeypatch) -> None:
    """A broker outage must not abort the sweep mid-way.

    The scan rows and the moved-forward schedules are committed before dispatch.
    If the dispatch call raised, every vendor after the failing one would keep
    its new next_scan_at while never being queued, so the sweep would silently
    skip them until the following interval. This drives the real failure — the
    broker refusing the publish — rather than stubbing the helper that handles it.
    """
    from zentra.workers import dispatch as dispatch_module
    from zentra.workers import tasks as tasks_module

    vendor, scan = _vendor_and_scan(account, db, "broker-down.io")
    from zentra.services import scans as scans_service

    scans_service.execute_scan(db, scan.id)
    vendor.next_scan_at = datetime.now(UTC) - timedelta(hours=1)
    db.commit()

    # Let dispatch run in the test environment, then make the broker publish fail.
    monkeypatch.setenv("ZENTRA_TEST_DISPATCH", "1")

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise ConnectionError("Error 111 connecting to redis:6379. Connection refused.")

    monkeypatch.setattr(tasks_module.run_scan_task, "delay", refuse)
    # Inline fallback is for interactive development; keep the test hermetic.
    monkeypatch.setattr(dispatch_module, "_run_inline", lambda _scan_id: None)

    result = tasks_module.rescan_due_vendors()

    # The sweep completed rather than raising, and reported nothing dispatched.
    assert result["queued"] >= 1
    assert result["dispatched"] == 0
