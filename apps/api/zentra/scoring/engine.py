"""Deterministic, explainable vendor risk scoring.

The engine takes normalized :class:`CheckResult` objects and produces a score
from 0 (no risk signals detected) to 100 (severe risk signals across the
board), together with a full breakdown that explains every point.

Design rules:

1. **Deterministic.** The same inputs always produce the same score. There is
   no randomness and no model inference.
2. **Explainable.** Every category reports the points it contributed and why.
3. **Failure is not risk.** A provider outage contributes zero risk points; it
   reduces coverage and confidence instead.
4. **Unknown is not risk.** An inconclusive check (e.g. DKIM without a known
   selector) contributes zero risk points.
5. **Bounded uncertainty.** Thin coverage adds a small, capped adjustment so a
   half-completed scan is never presented as a confident "Low risk"; it can
   never on its own push a vendor to "Critical".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from zentra.scanners.base import CheckResult, CheckStatus, CheckType, Severity
from zentra.scoring.config import (
    CATEGORY_CHECKS,
    Category,
    RiskLevel,
    ScoringConfig,
    risk_level_for,
)

_CHECK_TO_CATEGORY: dict[CheckType, Category] = {
    check: category for category, checks in CATEGORY_CHECKS.items() for check in checks
}


@dataclass
class CategoryScore:
    category: Category
    display_name: str
    description: str
    max_points: int
    points: float = 0.0
    assessed: bool = False
    confidence: float = 0.0
    contributing: list[dict[str, Any]] = field(default_factory=list)
    status: str = "not_assessed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "display_name": self.display_name,
            "description": self.description,
            "points": round(self.points, 1),
            "max_points": self.max_points,
            # Presented to users as "18/25" style sub-scores where a *lower*
            # number is better; the UI renders the same orientation.
            "assessed": self.assessed,
            "confidence": round(self.confidence, 3),
            "status": self.status,
            "contributing_checks": self.contributing,
        }


@dataclass
class ScoreResult:
    score: int
    #: ``None`` when coverage was too thin to publish a risk level at all.
    risk_level: RiskLevel | None
    #: Score before any severity floor was applied.
    base_score: int
    confidence: float
    coverage: float
    categories: list[CategoryScore]
    top_findings: list[dict[str, Any]]
    uncertainty_points: float
    checks_total: int
    checks_conclusive: int
    checks_failed_provider: int
    scoring_version: str
    #: Explanation of the floor that was applied, if any.
    applied_floor: dict[str, Any] | None = None
    inconclusive: bool = False

    @property
    def is_scorable(self) -> bool:
        """False when the result is too thin to present as a risk level."""
        return not self.inconclusive

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score if self.is_scorable else None,
            "raw_score": self.score,
            "base_score": self.base_score,
            "applied_floor": self.applied_floor,
            "risk_level": self.risk_level.value if self.risk_level else None,
            "is_scorable": self.is_scorable,
            "confidence": round(self.confidence, 3),
            "coverage": round(self.coverage, 3),
            "inconclusive": self.inconclusive,
            "uncertainty_points": round(self.uncertainty_points, 1),
            "scoring_version": self.scoring_version,
            "checks": {
                "total": self.checks_total,
                "conclusive": self.checks_conclusive,
                "provider_unavailable": self.checks_failed_provider,
            },
            "categories": [c.to_dict() for c in self.categories],
            "top_findings": self.top_findings,
        }


def _category_for(check: CheckResult) -> Category | None:
    return _CHECK_TO_CATEGORY.get(check.check_type)


def calculate_score(results: list[CheckResult], config: ScoringConfig | None = None) -> ScoreResult:
    """Score a set of normalized check results."""
    from zentra.scoring.config import DEFAULT_CONFIG

    cfg = config or DEFAULT_CONFIG

    categories: dict[Category, CategoryScore] = {
        category: CategoryScore(
            category=category,
            display_name=weight.display_name,
            description=weight.description,
            max_points=weight.max_points,
        )
        for category, weight in cfg.weights.items()
    }

    grouped: dict[Category, list[CheckResult]] = {c: [] for c in categories}
    for result in results:
        category = _category_for(result)
        if category is not None:
            grouped[category].append(result)

    checks_conclusive = 0
    provider_failures = 0

    for category, checks in grouped.items():
        entry = categories[category]
        if not checks:
            continue

        conclusive = [c for c in checks if c.is_conclusive]
        errored = [c for c in checks if c.status is CheckStatus.ERROR]
        provider_failures += len(errored)
        checks_conclusive += len(conclusive)

        if not conclusive:
            entry.status = "unavailable" if errored else "not_assessed"
            entry.assessed = False
            entry.confidence = 0.0
            continue

        entry.assessed = True
        entry.confidence = sum(c.confidence for c in conclusive) / len(conclusive)

        # Rank problems worst-first, then apply diminishing returns so a single
        # noisy category cannot swamp the score.
        problems = sorted(
            (c for c in conclusive if c.is_problem),
            key=lambda c: (
                -cfg.severity_impact[c.severity],
                -(c.confidence),
            ),
        )
        weight = cfg.weights[category]
        points = 0.0
        for index, check in enumerate(problems):
            impact = cfg.severity_impact[check.severity]
            if impact <= 0:
                continue
            if check.confidence < cfg.min_confidence:
                # Too speculative to move the score; still surfaced as a finding.
                entry.contributing.append(_contribution(check, 0.0, "below confidence threshold"))
                continue
            if check.status is CheckStatus.WARN:
                impact *= cfg.warn_multiplier
            impact *= check.confidence
            impact *= cfg.decay**index
            contribution = weight.max_points * impact
            points += contribution
            entry.contributing.append(_contribution(check, contribution, None))

        entry.points = min(points, float(weight.max_points))
        if entry.points <= 0:
            entry.status = "clear"
        elif entry.points >= weight.max_points * 0.66:
            entry.status = "severe"
        elif entry.points >= weight.max_points * 0.25:
            entry.status = "attention"
        else:
            entry.status = "minor"

    # ---------------------------------------------------------------- coverage
    weighted_assessed = sum(
        cfg.weights[c].max_points for c, entry in categories.items() if entry.assessed
    )
    total_weight = sum(w.max_points for w in cfg.weights.values())
    coverage = weighted_assessed / total_weight if total_weight else 0.0

    base_points = sum(entry.points for entry in categories.values())

    # Bounded uncertainty: unassessed weight is treated as *unknown*, not as
    # risk. We add a small fraction of the missing weight so a thin scan cannot
    # be presented as a confident clean bill of health.
    missing_fraction = 1.0 - coverage
    uncertainty = min(
        missing_fraction * cfg.coverage.max_uncertainty_points,
        float(cfg.coverage.max_uncertainty_points),
    )

    base_score = round(min(base_points + uncertainty, 100.0))
    score, applied_floor = _apply_severity_floor(base_score, results, cfg)
    assessed_categories = sum(1 for entry in categories.values() if entry.assessed)
    # Too few categories, or too little of the weighted check surface, means we
    # decline to publish a risk level rather than presenting a confident "Low"
    # that is really "we could not look".
    inconclusive = (
        assessed_categories < cfg.coverage.min_categories_for_score
        or coverage < cfg.coverage.inconclusive_threshold
    )

    # Confidence blends per-check confidence with coverage: a highly confident
    # check set that only covers a third of the categories is still a
    # low-confidence overall assessment.
    confidences = [entry.confidence for entry in categories.values() if entry.assessed]
    signal_confidence = sum(confidences) / len(confidences) if confidences else 0.0
    confidence = round(signal_confidence * (0.4 + 0.6 * coverage), 3)

    ordered = sorted(
        categories.values(),
        key=lambda e: (-e.points, -e.max_points),
    )

    return ScoreResult(
        score=score,
        base_score=base_score,
        applied_floor=applied_floor,
        risk_level=None if inconclusive else risk_level_for(score, cfg),
        confidence=confidence,
        coverage=round(coverage, 3),
        categories=ordered,
        top_findings=_top_findings(results),
        uncertainty_points=uncertainty,
        checks_total=len(results),
        checks_conclusive=checks_conclusive,
        checks_failed_provider=provider_failures,
        scoring_version=cfg.version,
        inconclusive=inconclusive,
    )


def _apply_severity_floor(
    base_score: int, results: list[CheckResult], cfg: ScoringConfig
) -> tuple[int, dict[str, Any] | None]:
    """Raise the score to the floor implied by the worst conclusive findings."""
    best_floor = 0
    reason: dict[str, Any] | None = None
    for severity, (single, multiple) in cfg.severity_floors.items():
        matching = [
            r
            for r in results
            if r.is_problem and r.severity is severity and r.confidence >= cfg.min_floor_confidence
        ]
        if not matching:
            continue
        floor = multiple if len(matching) >= 2 else single
        if floor > best_floor:
            best_floor = floor
            reason = {
                "severity": severity.value,
                "finding_count": len(matching),
                "floor": floor,
                "explanation": (
                    f"{len(matching)} {severity.value}-severity finding(s) set a minimum "
                    f"score of {floor}."
                ),
                "check_types": [r.check_type.value for r in matching[:5]],
            }
    if best_floor > base_score:
        return best_floor, reason
    return base_score, None


def _contribution(check: CheckResult, points: float, note: str | None) -> dict[str, Any]:
    return {
        "check_type": check.check_type.value,
        "status": check.status.value,
        "severity": check.severity.value,
        "summary": check.summary,
        "confidence": round(check.confidence, 3),
        "points": round(points, 1),
        "note": note,
        "source": check.source,
    }


def rank_problems(results: list[CheckResult]) -> list[CheckResult]:
    """Order problems worst-first.

    Ties on severity are broken by the weight of the scoring category, so a
    medium-severity exposure issue outranks a medium-severity web-hardening
    issue. This keeps the headline finding aligned with what actually moved
    the score.
    """
    from zentra.scoring.config import CATEGORY_WEIGHTS

    def sort_key(check: CheckResult) -> tuple[int, int, float]:
        category = _category_for(check)
        weight = CATEGORY_WEIGHTS[category].max_points if category else 0
        return (-check.severity.rank, -weight, -check.confidence)

    problems = [r for r in results if r.is_problem and r.severity.rank > Severity.INFO.rank]
    return sorted(problems, key=sort_key)


def _top_findings(results: list[CheckResult], limit: int = 5) -> list[dict[str, Any]]:
    problems = rank_problems(results)
    return [
        {
            "check_type": r.check_type.value,
            "title": r.title or r.summary,
            "summary": r.summary,
            "severity": r.severity.value,
            "status": r.status.value,
            "recommendation": r.recommendation,
            "source": r.source,
            "confidence": round(r.confidence, 3),
        }
        for r in problems[:limit]
    ]
