"""PostgreSQL Row Level Security.

The API already enforces tenancy in every query. These tests exercise the
database's own last line of defence: a connection acting as the Supabase
`authenticated` role with a given user's JWT claim must not be able to read or
write another organization's rows, even with a raw SQL statement.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from tests.conftest import Account
from zentra.config import get_settings
from zentra.db.session import engine_for


@pytest.fixture
def rls_connection() -> Iterator:
    """A connection that behaves like a Supabase end-user session."""
    engine = engine_for(get_settings().test_database_url)
    with engine.connect() as connection:
        try:
            yield connection
        finally:
            reset_role(connection)


def as_user(connection, user_id: uuid.UUID):
    """Switch the connection to the `authenticated` role with a user claim."""
    connection.rollback()
    connection.execute(text("SET ROLE authenticated"))
    connection.execute(
        text("SELECT set_config('request.jwt.claims', :claims, false)"),
        {"claims": f'{{"sub": "{user_id}", "role": "authenticated"}}'},
    )


def reset_role(connection) -> None:
    connection.rollback()
    connection.execute(text("RESET ROLE"))
    connection.execute(text("SELECT set_config('request.jwt.claims', '', false)"))
    # Commit so the reset survives: this connection goes back to a shared pool,
    # and a rolled-back RESET ROLE would leave it stuck as `authenticated`.
    connection.commit()


@pytest.fixture
def two_tenants(account: Account, other_account: Account) -> dict:
    account.post("/api/v1/vendors", json={"name": "Acme Vendor", "domain": "acme-vendor.io"})
    other_account.post(
        "/api/v1/vendors", json={"name": "Rival Vendor", "domain": "rival-vendor.io"}
    )
    return {"acme": account, "rival": other_account}


def test_rls_is_enabled_and_forced_on_every_tenant_table(rls_connection) -> None:
    rows = rls_connection.execute(
        text(
            """
            select relname, relrowsecurity, relforcerowsecurity
            from pg_class
            where relnamespace = 'public'::regnamespace
              and relkind = 'r'
              and relname in (
                'users','organizations','organization_members','vendors','scans',
                'scan_results','findings','alerts','api_keys','reports',
                'report_exports','audit_logs','subscriptions','integration_connections',
                'slack_workspaces','invitations','finding_status_history',
                'vendor_domains','webhook_events','public_scans','benchmark_data'
              )
            """
        )
    ).all()
    assert len(rows) == 21
    for name, enabled, forced in rows:
        assert enabled is True, f"RLS not enabled on {name}"
        assert forced is True, f"RLS not forced on {name}"


def test_authenticated_role_sees_only_its_own_vendors(two_tenants: dict, rls_connection) -> None:
    acme = two_tenants["acme"]
    rival = two_tenants["rival"]
    try:
        as_user(rls_connection, acme.user_id)
        domains = [r[0] for r in rls_connection.execute(text("select domain from vendors")).all()]
        assert domains == ["acme-vendor.io"]

        as_user(rls_connection, rival.user_id)
        domains = [r[0] for r in rls_connection.execute(text("select domain from vendors")).all()]
        assert domains == ["rival-vendor.io"]
    finally:
        reset_role(rls_connection)


def test_authenticated_role_cannot_read_another_organizations_scans_or_findings(
    two_tenants: dict, rls_connection, db
) -> None:
    from zentra.db.models import Scan, Vendor
    from zentra.services import scans as scans_service

    vendor = db.query(Vendor).filter(Vendor.domain == "acme-vendor.io").one()
    scan = db.query(Scan).filter(Scan.vendor_id == vendor.id).one()
    scans_service.execute_scan(db, scan.id)
    db.commit()

    acme_org = two_tenants["acme"].organization_id
    try:
        as_user(rls_connection, two_tenants["rival"].user_id)
        for table in ("scans", "scan_results", "findings", "alerts", "reports", "audit_logs"):
            count = rls_connection.execute(
                text(f"select count(*) from {table} where organization_id = :org"),
                {"org": acme_org},
            ).scalar_one()
            assert count == 0, f"{table} leaked across tenants"
        # The rival still sees their own rows, so this is isolation, not an
        # empty database.
        own = rls_connection.execute(text("select count(*) from scans")).scalar_one()
        assert own >= 1
    finally:
        reset_role(rls_connection)


def test_authenticated_role_cannot_insert_into_another_organization(
    two_tenants: dict, rls_connection
) -> None:
    acme_org = two_tenants["acme"].organization_id
    rival_user = two_tenants["rival"].user_id
    try:
        as_user(rls_connection, rival_user)
        with pytest.raises(ProgrammingError):
            rls_connection.execute(
                text(
                    "insert into vendors (organization_id, name, domain) "
                    "values (:org, 'Injected', 'injected.io')"
                ),
                {"org": acme_org},
            )
    finally:
        reset_role(rls_connection)


def test_authenticated_role_cannot_update_another_organizations_vendor(
    two_tenants: dict, rls_connection
) -> None:
    try:
        as_user(rls_connection, two_tenants["rival"].user_id)
        result = rls_connection.execute(
            text("update vendors set name = 'Hijacked' where domain = 'acme-vendor.io'")
        )
        # The row is invisible, so the update matches nothing.
        assert result.rowcount == 0
        rls_connection.commit()
    finally:
        reset_role(rls_connection)

    as_user(rls_connection, two_tenants["acme"].user_id)
    try:
        name = rls_connection.execute(
            text("select name from vendors where domain = 'acme-vendor.io'")
        ).scalar_one()
        assert name == "Acme Vendor"
    finally:
        reset_role(rls_connection)


def test_authenticated_role_cannot_delete_another_organizations_vendor(
    two_tenants: dict, rls_connection
) -> None:
    try:
        as_user(rls_connection, two_tenants["rival"].user_id)
        result = rls_connection.execute(text("delete from vendors where domain = 'acme-vendor.io'"))
        assert result.rowcount == 0
        rls_connection.commit()
    finally:
        reset_role(rls_connection)


def test_authenticated_role_cannot_read_api_key_hashes(
    two_tenants: dict, rls_connection, db, grant_plan
) -> None:
    acme = two_tenants["acme"]
    grant_plan(acme.organization_id, "scale")
    acme.post("/api/v1/api-keys", json={"name": "CI"})

    try:
        as_user(rls_connection, acme.user_id)
        # Metadata columns are granted...
        rls_connection.execute(text("select id, name, key_prefix from api_keys")).all()
        # ...but the hash column is not.
        with pytest.raises(ProgrammingError):
            rls_connection.execute(text("select key_hash from api_keys")).all()
    finally:
        reset_role(rls_connection)


def test_authenticated_role_cannot_read_integration_secrets(
    two_tenants: dict, rls_connection, db
) -> None:
    from zentra.db.models import IntegrationConnection

    db.add(
        IntegrationConnection(
            organization_id=two_tenants["acme"].organization_id,
            provider="teams",
            encrypted_secret="gAAAAA-encrypted",
            status="active",
        )
    )
    db.commit()
    try:
        as_user(rls_connection, two_tenants["acme"].user_id)
        rls_connection.execute(
            text("select id, provider, status from integration_connections")
        ).all()
        with pytest.raises(ProgrammingError):
            rls_connection.execute(
                text("select encrypted_secret from integration_connections")
            ).all()
    finally:
        reset_role(rls_connection)


def test_authenticated_role_cannot_read_backend_only_tables(
    two_tenants: dict, rls_connection, db
) -> None:
    from zentra.db.models import PublicScan, WebhookEvent

    db.add(WebhookEvent(provider="stripe", event_id="evt_rls_1", event_type="ping"))
    db.add(PublicScan(domain="public-scan.io", score=10, risk_level="low"))
    db.commit()
    for table in ("webhook_events", "public_scans"):
        try:
            # Re-assert the role for each table: a failed statement aborts the
            # transaction, and rolling back would drop SET ROLE with it.
            as_user(rls_connection, two_tenants["acme"].user_id)
            with pytest.raises(ProgrammingError):
                rls_connection.execute(text(f"select * from {table}")).all()
        finally:
            reset_role(rls_connection)


def test_anon_role_can_read_nothing(two_tenants: dict, rls_connection) -> None:
    for table in ("vendors", "organizations", "users", "scans", "findings"):
        try:
            rls_connection.rollback()
            rls_connection.execute(text("SET ROLE anon"))
            with pytest.raises(ProgrammingError):
                rls_connection.execute(text(f"select * from {table}")).all()
        finally:
            reset_role(rls_connection)


def test_a_user_with_no_claim_sees_nothing(two_tenants: dict, rls_connection) -> None:
    try:
        rls_connection.rollback()
        rls_connection.execute(text("SET ROLE authenticated"))
        rls_connection.execute(text("SELECT set_config('request.jwt.claims', '', false)"))
        count = rls_connection.execute(text("select count(*) from vendors")).scalar_one()
        assert count == 0
    finally:
        reset_role(rls_connection)


def test_a_forged_claim_for_a_nonexistent_user_sees_nothing(
    two_tenants: dict, rls_connection
) -> None:
    try:
        as_user(rls_connection, uuid.uuid4())
        assert rls_connection.execute(text("select count(*) from vendors")).scalar_one() == 0
        assert rls_connection.execute(text("select count(*) from organizations")).scalar_one() == 0
    finally:
        reset_role(rls_connection)
