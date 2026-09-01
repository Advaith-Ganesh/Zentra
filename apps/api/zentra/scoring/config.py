"""Risk scoring configuration.

Every number that influences a Zentra risk score lives here. The engine itself
contains no magic constants, so the methodology can be reviewed, tuned and
published without reading the implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from zentra.scanners.base import CheckType, Severity


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


#: Inclusive lower bounds. A higher score means more risk.
RISK_THRESHOLDS: tuple[tuple[int, RiskLevel], ...] = (
    (75, RiskLevel.CRITICAL),
    (50, RiskLevel.HIGH),
    (25, RiskLevel.MEDIUM),
    (0, RiskLevel.LOW),
)


class Category(StrEnum):
    """Scoring categories shown in the score breakdown."""

    TLS = "tls"
    BREACH = "breach"
    DNS = "dns"
    EXPOSURE = "exposure"
    CVE = "cve"
    WEB = "web"


#: Which check types roll up into which scoring category.
CATEGORY_CHECKS: dict[Category, tuple[CheckType, ...]] = {
    Category.TLS: (CheckType.TLS_CERTIFICATE, CheckType.TLS_CONFIGURATION),
    Category.BREACH: (CheckType.BREACH_HISTORY,),
    Category.DNS: (CheckType.DNS_SPF, CheckType.DNS_DMARC, CheckType.DNS_DKIM, CheckType.DNS_CAA),
    Category.EXPOSURE: (CheckType.INTERNET_EXPOSURE,),
    Category.CVE: (CheckType.CVE_EXPOSURE,),
    Category.WEB: (CheckType.TECHNOLOGY_STACK, CheckType.HTTP_SECURITY_HEADERS),
}


@dataclass(frozen=True)
class CategoryWeight:
    """The maximum number of risk points a category can contribute."""

    category: Category
    max_points: int
    display_name: str
    description: str


#: Weights sum to 100. TLS and breach history carry the most weight because
#: they are the highest-signal, highest-confidence checks available from
#: public sources; low-confidence technology signals carry the least.
CATEGORY_WEIGHTS: dict[Category, CategoryWeight] = {
    Category.TLS: CategoryWeight(
        Category.TLS, 25, "TLS / certificate", "Encryption in transit and certificate validity."
    ),
    Category.BREACH: CategoryWeight(
        Category.BREACH, 20, "Breach history", "Publicly catalogued breaches of this domain."
    ),
    Category.EXPOSURE: CategoryWeight(
        Category.EXPOSURE, 20, "Internet exposure", "Services reachable from the public internet."
    ),
    Category.CVE: CategoryWeight(
        Category.CVE, 15, "Known vulnerabilities", "Published CVEs matching disclosed software."
    ),
    Category.DNS: CategoryWeight(
        Category.DNS,
        15,
        "Email / DNS security",
        "Protection against email spoofing of this domain.",
    ),
    Category.WEB: CategoryWeight(
        Category.WEB, 5, "Web hardening", "Browser security headers and disclosed technology."
    ),
}

TOTAL_POINTS = sum(w.max_points for w in CATEGORY_WEIGHTS.values())

#: Fraction of a category's budget consumed by a single problem of each
#: severity, before confidence weighting.
SEVERITY_IMPACT: dict[Severity, float] = {
    Severity.CRITICAL: 1.00,
    Severity.HIGH: 0.72,
    Severity.MEDIUM: 0.40,
    Severity.LOW: 0.16,
    Severity.INFO: 0.0,
}

#: Additional problems in the same category add progressively less, so a single
#: noisy category cannot dominate the score.
ADDITIONAL_FINDING_DECAY = 0.45

#: A WARN counts for less than a FAIL of the same severity.
WARN_MULTIPLIER = 0.6

#: Minimum confidence a check needs before it contributes any risk at all.
MIN_CONTRIBUTING_CONFIDENCE = 0.25

#: Severity floors.
#:
#: The weighted sum alone under-states a single decisive problem: no category
#: is worth more than 25 points, so an expired certificate could never exceed
#: "Medium" on the sum alone. A floor fixes that without distorting the rest of
#: the model: a conclusive finding of the given severity sets a *minimum*
#: score, and is reported explicitly in the breakdown so the jump is
#: explainable.
#:
#: Floors only ever apply to conclusive, sufficiently-confident findings, so a
#: provider outage or a low-confidence signal can never trigger one.
SEVERITY_FLOORS: dict[Severity, tuple[int, int]] = {
    # severity: (floor for one such finding, floor for two or more)
    Severity.CRITICAL: (50, 75),
    Severity.HIGH: (25, 50),
}

#: Minimum confidence for a finding to be allowed to raise a floor.
MIN_FLOOR_CONFIDENCE = 0.5


@dataclass(frozen=True)
class CoveragePolicy:
    """How missing data affects the score and the reported confidence.

    Missing data must never *invent* risk, and must never be silently reported
    as safety. Zentra's answer is to score only what was assessed and to state
    coverage explicitly, with a small, bounded uncertainty adjustment that pulls
    a sparsely-covered result away from a confident "Low".
    """

    #: Below this coverage fraction the verdict is explicitly flagged as partial.
    partial_threshold: float = 0.7
    #: Below this, the result is presented as inconclusive.
    inconclusive_threshold: float = 0.4
    #: Maximum points added to reflect unassessed categories. Bounded and small:
    #: it nudges a thin scan out of "Low", it never manufactures "Critical".
    max_uncertainty_points: int = 12
    #: A scan with no conclusive checks at all cannot produce a risk level.
    min_categories_for_score: int = 2


COVERAGE_POLICY = CoveragePolicy()


@dataclass(frozen=True)
class ScoringConfig:
    weights: dict[Category, CategoryWeight] = field(default_factory=lambda: CATEGORY_WEIGHTS)
    thresholds: tuple[tuple[int, RiskLevel], ...] = RISK_THRESHOLDS
    severity_impact: dict[Severity, float] = field(default_factory=lambda: SEVERITY_IMPACT)
    decay: float = ADDITIONAL_FINDING_DECAY
    warn_multiplier: float = WARN_MULTIPLIER
    min_confidence: float = MIN_CONTRIBUTING_CONFIDENCE
    severity_floors: dict[Severity, tuple[int, int]] = field(
        default_factory=lambda: SEVERITY_FLOORS
    )
    min_floor_confidence: float = MIN_FLOOR_CONFIDENCE
    coverage: CoveragePolicy = COVERAGE_POLICY
    version: str = "1.0.0"


DEFAULT_CONFIG = ScoringConfig()


def risk_level_for(score: int, config: ScoringConfig | None = None) -> RiskLevel:
    thresholds = (config or DEFAULT_CONFIG).thresholds
    for lower_bound, level in thresholds:
        if score >= lower_bound:
            return level
    return RiskLevel.LOW
