"""Internal platform administration.

Gated on ``users.is_platform_admin``, which is set server-side from the
``ZENTRA_ADMIN_EMAILS`` environment variable. There is no client-side flag that
can grant it, and API keys can never satisfy the dependency. Unauthorized
callers receive 404 so the surface is not discoverable.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from zentra.auth.deps import DbSession, PlatformAdmin
from zentra.config import get_settings
from zentra.core.feature_flags import all_flags
from zentra.core.ratelimit import redis_available
from zentra.db.models import (
    ApiKey,
    AuditLog,
    Organization,
    Scan,
    Subscription,
    User,
    Vendor,
    WebhookEvent,
)
from zentra.db.session import ping as db_ping

router = APIRouter(prefix="/admin", tags=["Admin"], include_in_schema=False)


@router.get("/overview")
async def overview(admin: PlatformAdmin, session: DbSession) -> dict[str, Any]:
    settings = get_settings()
    day_ago = datetime.now(UTC) - timedelta(days=1)

    counts = session.execute(
        select(
            select(func.count(User.id)).scalar_subquery(),
            select(func.count(Organization.id)).scalar_subquery(),
            select(func.count(Vendor.id)).scalar_subquery(),
            select(func.count(Scan.id)).scalar_subquery(),
        )
    ).one()

    scan_health = session.execute(
        select(Scan.status, func.count(Scan.id))
        .where(Scan.created_at >= day_ago)
        .group_by(Scan.status)
    ).all()

    plan_mix = session.execute(
        select(Subscription.plan, func.count(Subscription.id)).group_by(Subscription.plan)
    ).all()

    return {
        "environment": settings.environment,
        "mock_scanners": settings.use_mock_scanners,
        "feature_flags": all_flags(),
        "totals": {
            "users": counts[0],
            "organizations": counts[1],
            "vendors": counts[2],
            "scans": counts[3],
        },
        "scan_health_24h": {str(row[0]): int(row[1]) for row in scan_health},
        "plan_mix": {str(row[0]): int(row[1]) for row in plan_mix},
        "dependencies": {
            "database": "ok" if db_ping() else "unavailable",
            "redis": "ok" if redis_available() else "unavailable",
        },
    }


@router.get("/organizations")
async def organizations(
    admin: PlatformAdmin,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[dict[str, Any]]:
    rows = session.execute(
        select(
            Organization.id,
            Organization.name,
            Organization.slug,
            Organization.plan,
            Organization.created_at,
            Organization.is_demo,
            func.count(Vendor.id),
        )
        .outerjoin(Vendor, Vendor.organization_id == Organization.id)
        .group_by(Organization.id)
        .order_by(Organization.created_at.desc())
        .limit(limit)
    ).all()
    return [
        {
            "id": str(row[0]),
            "name": row[1],
            "slug": row[2],
            "plan": row[3],
            "created_at": row[4].isoformat(),
            "is_demo": row[5],
            "vendor_count": row[6],
        }
        for row in rows
    ]


@router.get("/scan-health")
async def scan_health(
    admin: PlatformAdmin,
    session: DbSession,
    hours: Annotated[int, Query(ge=1, le=168)] = 24,
) -> dict[str, Any]:
    since = datetime.now(UTC) - timedelta(hours=hours)
    by_status = session.execute(
        select(Scan.status, func.count(Scan.id))
        .where(Scan.created_at >= since)
        .group_by(Scan.status)
    ).all()
    failures = session.execute(
        select(Scan.error_code, func.count(Scan.id))
        .where(Scan.created_at >= since, Scan.status == "failed")
        .group_by(Scan.error_code)
        .order_by(func.count(Scan.id).desc())
        .limit(20)
    ).all()
    durations = session.execute(
        select(
            func.avg(func.extract("epoch", Scan.completed_at - Scan.started_at)),
            func.max(func.extract("epoch", Scan.completed_at - Scan.started_at)),
        ).where(Scan.completed_at.isnot(None), Scan.created_at >= since)
    ).one()
    return {
        "window_hours": hours,
        "by_status": {str(row[0]): int(row[1]) for row in by_status},
        "failure_reasons": {str(row[0] or "unknown"): int(row[1]) for row in failures},
        "avg_duration_seconds": round(float(durations[0]), 2) if durations[0] else None,
        "max_duration_seconds": round(float(durations[1]), 2) if durations[1] else None,
    }


@router.get("/queue")
async def queue_status(admin: PlatformAdmin, session: DbSession) -> dict[str, Any]:
    pending = session.execute(
        select(Scan.status, func.count(Scan.id))
        .where(Scan.status.in_(["queued", "running"]))
        .group_by(Scan.status)
    ).all()
    depth: dict[str, int] = {}
    try:
        from zentra.core.ratelimit import get_redis

        client = get_redis()
        depth["zentra"] = int(client.llen("zentra") or 0)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001 - queue depth is best-effort
        depth["zentra"] = -1
    return {
        "database": {str(row[0]): int(row[1]) for row in pending},
        "broker_queue_depth": depth,
    }


@router.get("/webhooks")
async def webhook_health(
    admin: PlatformAdmin,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[dict[str, Any]]:
    rows = session.execute(
        select(WebhookEvent).order_by(WebhookEvent.created_at.desc()).limit(limit)
    ).scalars()
    return [
        {
            "provider": r.provider,
            "event_type": r.event_type,
            "status": r.status,
            "error": r.error_message,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.get("/api-usage")
async def api_usage(admin: PlatformAdmin, session: DbSession) -> dict[str, Any]:
    active = session.execute(
        select(func.count(ApiKey.id)).where(ApiKey.revoked_at.is_(None))
    ).scalar_one()
    recently_used = session.execute(
        select(func.count(ApiKey.id)).where(
            ApiKey.last_used_at >= datetime.now(UTC) - timedelta(days=7)
        )
    ).scalar_one()
    return {"active_keys": int(active), "used_last_7_days": int(recently_used)}


@router.get("/audit")
async def recent_audit(
    admin: PlatformAdmin,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[dict[str, Any]]:
    rows = session.execute(
        select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    ).scalars()
    return [
        {
            "action": r.action,
            "organization_id": str(r.organization_id) if r.organization_id else None,
            "actor_type": r.actor_type,
            "resource_type": r.resource_type,
            "created_at": r.created_at.isoformat(),
            "request_id": r.request_id,
        }
        for r in rows
    ]
