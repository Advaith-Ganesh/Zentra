"""Vendor risk benchmarking.

Benchmarks are computed from aggregated, anonymized data only. Two rules are
enforced structurally rather than by convention:

1. A cohort is only stored, and only shown, when it contains at least
   ``benchmark_min_sample_size`` organizations. Below that, no benchmark is
   returned at all.
2. Only organizations that have opted in contribute to a cohort.

The UI reports the real sample size it is comparing against. It never claims a
sample Zentra does not have.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import distinct, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from zentra.config import get_settings
from zentra.core.feature_flags import Flag, is_enabled
from zentra.db.models import BenchmarkData, Organization, Vendor
from zentra.logging import get_logger

log = get_logger("zentra.benchmark")

METRIC_AVERAGE_VENDOR_SCORE = "average_vendor_score"


def cohort_key(industry: str | None, company_size: str | None) -> str:
    return f"{(industry or 'all').lower()}::{(company_size or 'all').lower()}"


def cohort_label(industry: str | None, company_size: str | None) -> str:
    if industry and company_size:
        return f"{industry} companies with {company_size} employees"
    if industry:
        return f"{industry} companies"
    if company_size:
        return f"companies with {company_size} employees"
    return "all Zentra customers"


def recompute(session: Session) -> int:
    """Recompute every cohort. Returns the number of cohorts stored."""
    settings = get_settings()
    minimum = settings.benchmark_min_sample_size

    # Per-organization average vendor score, opted-in organizations only.
    per_org = (
        select(
            Organization.id.label("organization_id"),
            Organization.industry.label("industry"),
            Organization.company_size.label("company_size"),
            func.avg(Vendor.current_score).label("avg_score"),
        )
        .join(Vendor, Vendor.organization_id == Organization.id)
        .where(
            Organization.deleted_at.is_(None),
            Organization.benchmark_opt_in.is_(True),
            Organization.is_demo.is_(False),
            Vendor.status == "active",
            Vendor.current_score.isnot(None),
        )
        .group_by(Organization.id, Organization.industry, Organization.company_size)
        .subquery()
    )

    stored = 0
    groupings: list[tuple[Any, Any]] = [
        (per_org.c.industry, per_org.c.company_size),
        (per_org.c.industry, None),
        (None, None),
    ]

    for industry_col, size_col in groupings:
        columns = [c for c in (industry_col, size_col) if c is not None]
        query = select(
            *columns,
            func.count(distinct(per_org.c.organization_id)).label("sample_size"),
            func.percentile_cont(0.25).within_group(per_org.c.avg_score).label("p25"),
            func.percentile_cont(0.5).within_group(per_org.c.avg_score).label("p50"),
            func.percentile_cont(0.75).within_group(per_org.c.avg_score).label("p75"),
            func.avg(per_org.c.avg_score).label("average"),
        )
        if columns:
            query = query.group_by(*columns)

        for row in session.execute(query).mappings():
            sample = int(row["sample_size"] or 0)
            if sample < minimum:
                # Too small to be meaningful, and too small to be anonymous.
                continue
            industry = row.get("industry")
            company_size = row.get("company_size")
            key = cohort_key(industry, company_size)
            statement = (
                insert(BenchmarkData)
                .values(
                    cohort_key=key,
                    industry=industry,
                    company_size=company_size,
                    metric=METRIC_AVERAGE_VENDOR_SCORE,
                    sample_size=sample,
                    p25=row["p25"],
                    p50=row["p50"],
                    p75=row["p75"],
                    average=row["average"],
                    computed_at=func.now(),
                )
                .on_conflict_do_update(
                    index_elements=[BenchmarkData.cohort_key, BenchmarkData.metric],
                    set_={
                        "sample_size": sample,
                        "p25": row["p25"],
                        "p50": row["p50"],
                        "p75": row["p75"],
                        "average": row["average"],
                        "computed_at": func.now(),
                    },
                )
            )
            session.execute(statement)
            stored += 1
    session.flush()
    return stored


def for_organization(session: Session, organization: Organization) -> dict[str, Any]:
    """Return the most specific cohort with a sufficient sample, if any."""
    settings = get_settings()
    if not is_enabled(Flag.BENCHMARKING):
        return {
            "available": False,
            "sample_size": 0,
            "message": "Benchmarking is not enabled for this deployment.",
        }

    your_average = session.execute(
        select(func.avg(Vendor.current_score)).where(
            Vendor.organization_id == organization.id,
            Vendor.status == "active",
            Vendor.current_score.isnot(None),
        )
    ).scalar()

    candidates = [
        (organization.industry, organization.company_size),
        (organization.industry, None),
        (None, None),
    ]
    for industry, company_size in candidates:
        record = session.execute(
            select(BenchmarkData).where(
                BenchmarkData.cohort_key == cohort_key(industry, company_size),
                BenchmarkData.metric == METRIC_AVERAGE_VENDOR_SCORE,
            )
        ).scalar_one_or_none()
        if record is None or record.sample_size < settings.benchmark_min_sample_size:
            continue
        return {
            "available": True,
            "cohort_label": cohort_label(industry, company_size),
            "sample_size": record.sample_size,
            "your_average_score": round(float(your_average), 1) if your_average else None,
            "cohort_median": float(record.p50) if record.p50 is not None else None,
            "cohort_p25": float(record.p25) if record.p25 is not None else None,
            "cohort_p75": float(record.p75) if record.p75 is not None else None,
            "message": (
                f"Compared with {record.sample_size} "
                f"{'organizations' if record.sample_size != 1 else 'organization'} in your "
                "benchmark group."
            ),
        }

    return {
        "available": False,
        "sample_size": 0,
        "your_average_score": round(float(your_average), 1) if your_average else None,
        "message": (
            "There is not yet enough anonymized data to produce a statistically meaningful "
            "benchmark for your cohort. Zentra will show one as soon as there is."
        ),
    }


def organization_vendor_count(session: Session, organization_id: uuid.UUID) -> int:
    return int(
        session.execute(
            select(func.count(Vendor.id)).where(Vendor.organization_id == organization_id)
        ).scalar_one()
    )
