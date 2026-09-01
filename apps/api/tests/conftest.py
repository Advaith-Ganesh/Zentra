"""Shared pytest fixtures.

Tests run against a real PostgreSQL database (Zentra's schema uses native
enums, JSONB, CITEXT, array columns and row-level security, none of which
SQLite can emulate). Each test gets a clean set of tables.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest

# Configure the environment before anything imports zentra.config.
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("USE_MOCK_SCANNERS", "true")
os.environ.setdefault("AUTH_PROVIDER", "local")
os.environ.setdefault("JWT_SECRET", "test-secret-" + "0" * 40)
os.environ.setdefault("EMAIL_PROVIDER", "console")
os.environ.setdefault("LOG_LEVEL", "WARNING")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SECRETS_ENCRYPTION_KEY", "sHRxYnPTt9EHwSGtQ1c1qE1MMBLNwoFbcHXCoI0uZQY=")
os.environ.setdefault(
    "TEST_DATABASE_URL",
    "postgresql+psycopg://postgres:postgres@127.0.0.1:5432/zentra_test",
)

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from zentra.config import get_settings, reset_settings_cache
from zentra.core.ratelimit import reset_local_state
from zentra.db.migrate import run_migrations
from zentra.db.session import SessionLocal, engine_for
from zentra.integrations.email.provider import ConsoleEmailProvider
from zentra.main import create_app

TABLES_IN_TRUNCATION_ORDER = [
    "audit_logs",
    "report_exports",
    "reports",
    "finding_status_history",
    "findings",
    "alerts",
    "scan_results",
    "scans",
    "vendor_domains",
    "vendors",
    "api_keys",
    "slack_workspaces",
    "integration_connections",
    "invitations",
    "subscriptions",
    "organization_members",
    "organizations",
    "users",
    "webhook_events",
    "public_scans",
    "benchmark_data",
]


@pytest.fixture(scope="session")
def _migrate() -> None:
    reset_settings_cache()
    settings = get_settings()
    run_migrations(settings.test_database_url)


@pytest.fixture
def clean_database(_migrate: None) -> Iterator[None]:
    """Truncate every table. Requested by any fixture that touches the database.

    Deliberately not autouse: pure unit tests (scoring, SSRF, domains) must run
    without a database.
    """
    settings = get_settings()
    engine = engine_for(settings.test_database_url)
    with engine.begin() as conn:
        conn.execute(
            text("TRUNCATE " + ", ".join(TABLES_IN_TRUNCATION_ORDER) + " RESTART IDENTITY CASCADE")
        )
    ConsoleEmailProvider.clear()
    reset_local_state()
    yield


@pytest.fixture
def db(clean_database: None) -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def app(clean_database: None):
    return create_app()


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


# --------------------------------------------------------------------- helpers
class Account:
    """A signed-up account plus its authenticated request headers."""

    def __init__(self, client: TestClient, payload: dict, password: str) -> None:
        self.client = client
        self.token = payload["access_token"]
        self.user_id = uuid.UUID(payload["user"]["id"])
        self.email = payload["user"]["email"]
        self.password = password
        self.organization_id = uuid.UUID(payload["organization"]["id"])
        self.organization_name = payload["organization"]["name"]

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, url: str, **kwargs):
        return self.client.get(url, headers=self.headers, **kwargs)

    def post(self, url: str, **kwargs):
        return self.client.post(url, headers=self.headers, **kwargs)

    def patch(self, url: str, **kwargs):
        return self.client.patch(url, headers=self.headers, **kwargs)

    def delete(self, url: str, **kwargs):
        return self.client.delete(url, headers=self.headers, **kwargs)


def signup(
    client: TestClient, *, email: str, org: str, password: str = "Correct-Horse-9!x"
) -> Account:
    response = client.post(
        "/api/v1/auth/signup",
        json={
            "email": email,
            "password": password,
            "full_name": "Test User",
            "organization_name": org,
            "industry": "Fintech",
            "company_size": "10-50",
        },
    )
    assert response.status_code == 201, response.text
    return Account(client, response.json(), password)


@pytest.fixture
def account(client: TestClient) -> Account:
    return signup(client, email="founder@acme-fintech.io", org="Acme Fintech")


@pytest.fixture
def other_account(client: TestClient) -> Account:
    return signup(client, email="founder@rival-corp.io", org="Rival Corp")


@pytest.fixture
def make_account(client: TestClient):
    def _factory(email: str, org: str) -> Account:
        return signup(client, email=email, org=org)

    return _factory


def set_plan(db: Session, organization_id: uuid.UUID, plan: str, status: str = "active") -> None:
    """Grant a plan directly, as a verified Stripe webhook would."""
    from zentra.core.entitlements import PLANS, Plan
    from zentra.db.models import Organization, Subscription

    subscription = (
        db.query(Subscription).filter(Subscription.organization_id == organization_id).one()
    )
    subscription.plan = plan
    subscription.status = status
    organization = db.get(Organization, organization_id)
    organization.plan = plan
    organization.vendor_limit = PLANS[Plan(plan)].vendor_limit
    db.commit()


@pytest.fixture
def grant_plan(db: Session):
    def _grant(organization_id: uuid.UUID, plan: str, status: str = "active") -> None:
        set_plan(db, organization_id, plan, status)

    return _grant


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
