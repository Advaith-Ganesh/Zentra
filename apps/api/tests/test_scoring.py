"""Risk scoring engine.

Every case here is deterministic: the same normalized check results must always
produce the same score. The most important properties under test are the ones
that keep Zentra honest — a provider outage is not a security failure, an
inconclusive check is not risk, and thin coverage never produces a confident
"Low risk".
"""

from __future__ import annotations

import pytest

from zentra.scanners.base import CheckResult, CheckStatus, CheckType, Severity
from zentra.scoring.config import (
    CATEGORY_WEIGHTS,
    TOTAL_POINTS,
    Category,
    RiskLevel,
    risk_level_for,
)
from zentra.scoring.engine import calculate_score
from zentra.scoring.verdict import build_verdict


def check(
    check_type: CheckType,
    status: CheckStatus,
    severity: Severity = Severity.INFO,
    *,
    confidence: float = 1.0,
    summary: str = "Test check result.",
    title: str | None = None,
    recommendation: str | None = None,
) -> CheckResult:
    return CheckResult(
        check_type=check_type,
        status=status,
        severity=severity,
        summary=summary,
        source="test",
        confidence=confidence,
        title=title,
        recommendation=recommendation,
    )


def clean_results() -> list[CheckResult]:
    """A vendor where every check completed and everything passed."""
    return [
        check(CheckType.TLS_CERTIFICATE, CheckStatus.PASS),
        check(CheckType.TLS_CONFIGURATION, CheckStatus.PASS),
        check(CheckType.DNS_SPF, CheckStatus.PASS),
        check(CheckType.DNS_DMARC, CheckStatus.PASS),
        check(CheckType.DNS_DKIM, CheckStatus.PASS),
        check(CheckType.DNS_CAA, CheckStatus.PASS),
        check(CheckType.BREACH_HISTORY, CheckStatus.PASS, confidence=0.9),
        check(CheckType.INTERNET_EXPOSURE, CheckStatus.PASS, confidence=0.85),
        check(CheckType.CVE_EXPOSURE, CheckStatus.PASS, confidence=0.7),
        check(CheckType.TECHNOLOGY_STACK, CheckStatus.PASS, confidence=0.6),
        check(CheckType.HTTP_SECURITY_HEADERS, CheckStatus.PASS, confidence=0.9),
    ]


def replace(results: list[CheckResult], new: CheckResult) -> list[CheckResult]:
    return [r for r in results if r.check_type is not new.check_type] + [new]


# --------------------------------------------------------------- configuration
def test_category_weights_sum_to_one_hundred() -> None:
    assert TOTAL_POINTS == 100
    assert sum(w.max_points for w in CATEGORY_WEIGHTS.values()) == 100


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (0, RiskLevel.LOW),
        (24, RiskLevel.LOW),
        (25, RiskLevel.MEDIUM),
        (49, RiskLevel.MEDIUM),
        (50, RiskLevel.HIGH),
        (74, RiskLevel.HIGH),
        (75, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_boundaries(score: int, level: RiskLevel) -> None:
    assert risk_level_for(score) is level


# --------------------------------------------------------------------- scoring
def test_perfect_vendor_scores_zero() -> None:
    result = calculate_score(clean_results())
    assert result.score == 0
    assert result.risk_level is RiskLevel.LOW
    assert result.coverage == 1.0
    assert result.is_scorable
    assert result.top_findings == []


def test_scoring_is_deterministic() -> None:
    results = clean_results()
    assert calculate_score(results).score == calculate_score(results).score


def test_minor_dns_weakness_stays_low() -> None:
    results = replace(clean_results(), check(CheckType.DNS_CAA, CheckStatus.WARN, Severity.LOW))
    result = calculate_score(results)
    assert result.risk_level is RiskLevel.LOW
    assert 0 < result.score < 10


def test_expired_certificate_is_high_risk() -> None:
    results = replace(
        clean_results(),
        check(
            CheckType.TLS_CERTIFICATE,
            CheckStatus.FAIL,
            Severity.CRITICAL,
            title="Expired TLS certificate",
        ),
    )
    result = calculate_score(results)
    assert result.risk_level is RiskLevel.HIGH
    assert result.applied_floor is not None
    assert result.applied_floor["severity"] == "critical"


def test_weak_tls_configuration_moves_the_score_but_is_not_critical() -> None:
    results = replace(
        clean_results(),
        check(CheckType.TLS_CONFIGURATION, CheckStatus.FAIL, Severity.MEDIUM),
    )
    result = calculate_score(results)
    assert result.score > 0
    assert result.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM)


def test_old_breach_warns_but_does_not_dominate() -> None:
    results = replace(
        clean_results(),
        check(CheckType.BREACH_HISTORY, CheckStatus.WARN, Severity.MEDIUM, confidence=0.95),
    )
    result = calculate_score(results)
    assert result.risk_level is RiskLevel.LOW
    breach = next(c for c in result.categories if c.category is Category.BREACH)
    assert 0 < breach.points < breach.max_points


def test_credential_breach_is_high_risk() -> None:
    results = replace(
        clean_results(),
        check(CheckType.BREACH_HISTORY, CheckStatus.FAIL, Severity.CRITICAL, confidence=0.95),
    )
    result = calculate_score(results)
    assert result.risk_level is RiskLevel.HIGH


def test_multiple_exposed_ports_raise_exposure_points() -> None:
    results = replace(
        clean_results(),
        check(CheckType.INTERNET_EXPOSURE, CheckStatus.FAIL, Severity.HIGH, confidence=0.85),
    )
    result = calculate_score(results)
    exposure = next(c for c in result.categories if c.category is Category.EXPOSURE)
    assert exposure.points > 0
    assert result.risk_level is RiskLevel.MEDIUM


def test_critical_cve_reaches_high_despite_small_category_weight() -> None:
    """CVE is only worth 15 points, so the floor is what makes this High."""
    results = replace(
        clean_results(),
        check(CheckType.CVE_EXPOSURE, CheckStatus.FAIL, Severity.CRITICAL, confidence=0.7),
    )
    result = calculate_score(results)
    assert result.risk_level is RiskLevel.HIGH
    assert result.base_score < result.score


def test_two_critical_findings_reach_critical() -> None:
    results = clean_results()
    results = replace(
        results, check(CheckType.TLS_CERTIFICATE, CheckStatus.FAIL, Severity.CRITICAL)
    )
    results = replace(
        results,
        check(CheckType.BREACH_HISTORY, CheckStatus.FAIL, Severity.CRITICAL, confidence=0.95),
    )
    result = calculate_score(results)
    assert result.risk_level is RiskLevel.CRITICAL
    assert result.score >= 75


def test_everything_failing_is_critical() -> None:
    results = [
        check(CheckType.TLS_CERTIFICATE, CheckStatus.FAIL, Severity.CRITICAL),
        check(CheckType.TLS_CONFIGURATION, CheckStatus.FAIL, Severity.HIGH),
        check(CheckType.BREACH_HISTORY, CheckStatus.FAIL, Severity.CRITICAL, confidence=0.95),
        check(CheckType.INTERNET_EXPOSURE, CheckStatus.FAIL, Severity.HIGH, confidence=0.85),
        check(CheckType.CVE_EXPOSURE, CheckStatus.FAIL, Severity.CRITICAL, confidence=0.7),
        check(CheckType.DNS_SPF, CheckStatus.FAIL, Severity.MEDIUM),
        check(CheckType.DNS_DMARC, CheckStatus.FAIL, Severity.MEDIUM),
        check(CheckType.HTTP_SECURITY_HEADERS, CheckStatus.WARN, Severity.MEDIUM, confidence=0.9),
    ]
    result = calculate_score(results)
    assert result.risk_level is RiskLevel.CRITICAL
    assert result.score <= 100


def test_score_never_exceeds_one_hundred() -> None:
    results = [check(ct, CheckStatus.FAIL, Severity.CRITICAL) for ct in CheckType]
    assert calculate_score(results).score <= 100


# ------------------------------------------------- provider failures and unknowns
def test_provider_error_contributes_no_risk() -> None:
    """The single most important scoring invariant."""
    clean = calculate_score(clean_results())
    with_error = calculate_score(
        replace(clean_results(), check(CheckType.CVE_EXPOSURE, CheckStatus.ERROR, confidence=0.0))
    )
    cve = next(c for c in with_error.categories if c.category is Category.CVE)
    assert cve.points == 0
    assert cve.assessed is False
    assert cve.status == "unavailable"
    # The score rises only by the bounded uncertainty adjustment, and stays low.
    assert with_error.score > clean.score
    assert with_error.risk_level is RiskLevel.LOW


def test_error_result_severity_is_forced_to_info() -> None:
    """A scanner cannot smuggle risk in through an errored result."""
    result = CheckResult(
        check_type=CheckType.TLS_CERTIFICATE,
        status=CheckStatus.ERROR,
        severity=Severity.CRITICAL,
        summary="provider down",
        source="test",
    )
    assert result.severity is Severity.INFO
    assert result.is_conclusive is False


def test_unknown_result_contributes_no_risk() -> None:
    """DKIM without a discoverable selector must not become a finding."""
    results = replace(
        clean_results(),
        check(CheckType.DNS_DKIM, CheckStatus.UNKNOWN, confidence=0.0),
    )
    result = calculate_score(results)
    assert all(f["check_type"] != CheckType.DNS_DKIM.value for f in result.top_findings)
    assert result.risk_level is RiskLevel.LOW


def test_all_providers_down_is_inconclusive_not_low_risk() -> None:
    results = [
        check(ct, CheckStatus.ERROR, confidence=0.0)
        for ct in (
            CheckType.TLS_CERTIFICATE,
            CheckType.BREACH_HISTORY,
            CheckType.INTERNET_EXPOSURE,
            CheckType.CVE_EXPOSURE,
            CheckType.DNS_SPF,
            CheckType.HTTP_SECURITY_HEADERS,
        )
    ]
    result = calculate_score(results)
    assert result.is_scorable is False
    assert result.risk_level is None
    assert result.coverage == 0.0
    assert result.confidence == 0.0


def test_thin_coverage_declines_to_publish_a_risk_level() -> None:
    """Half the scanners failing must not read as a clean bill of health."""
    results = [
        check(CheckType.DNS_SPF, CheckStatus.PASS),
        check(CheckType.HTTP_SECURITY_HEADERS, CheckStatus.PASS, confidence=0.9),
        check(CheckType.TLS_CERTIFICATE, CheckStatus.ERROR, confidence=0.0),
        check(CheckType.BREACH_HISTORY, CheckStatus.ERROR, confidence=0.0),
        check(CheckType.INTERNET_EXPOSURE, CheckStatus.ERROR, confidence=0.0),
    ]
    result = calculate_score(results)
    assert result.coverage < 0.4
    assert result.is_scorable is False
    assert result.risk_level is None


def test_partial_coverage_scores_but_reports_reduced_confidence() -> None:
    results = [
        check(CheckType.TLS_CERTIFICATE, CheckStatus.PASS),
        check(CheckType.TLS_CONFIGURATION, CheckStatus.PASS),
        check(CheckType.BREACH_HISTORY, CheckStatus.PASS, confidence=0.9),
        check(CheckType.DNS_SPF, CheckStatus.PASS),
        check(CheckType.INTERNET_EXPOSURE, CheckStatus.ERROR, confidence=0.0),
        check(CheckType.CVE_EXPOSURE, CheckStatus.ERROR, confidence=0.0),
    ]
    result = calculate_score(results)
    full = calculate_score(clean_results())
    assert result.is_scorable
    assert 0.4 <= result.coverage < 1.0
    assert result.confidence < full.confidence


def test_low_confidence_signal_does_not_move_the_score() -> None:
    results = replace(
        clean_results(),
        check(CheckType.CVE_EXPOSURE, CheckStatus.FAIL, Severity.HIGH, confidence=0.1),
    )
    result = calculate_score(results)
    cve = next(c for c in result.categories if c.category is Category.CVE)
    assert cve.points == 0
    assert any(c["note"] for c in cve.contributing)


def test_low_confidence_finding_cannot_trigger_a_floor() -> None:
    results = replace(
        clean_results(),
        check(CheckType.CVE_EXPOSURE, CheckStatus.FAIL, Severity.CRITICAL, confidence=0.2),
    )
    result = calculate_score(results)
    assert result.applied_floor is None
    assert result.risk_level is RiskLevel.LOW


def test_diminishing_returns_within_a_category() -> None:
    """Two DNS problems must cost less than twice one DNS problem."""
    one = calculate_score(
        replace(clean_results(), check(CheckType.DNS_SPF, CheckStatus.FAIL, Severity.MEDIUM))
    )
    two = calculate_score(
        replace(
            replace(clean_results(), check(CheckType.DNS_SPF, CheckStatus.FAIL, Severity.MEDIUM)),
            check(CheckType.DNS_DMARC, CheckStatus.FAIL, Severity.MEDIUM),
        )
    )
    dns_one = next(c for c in one.categories if c.category is Category.DNS).points
    dns_two = next(c for c in two.categories if c.category is Category.DNS).points
    assert dns_one < dns_two < dns_one * 2


def test_category_points_are_capped_at_the_category_weight() -> None:
    results = [
        check(CheckType.DNS_SPF, CheckStatus.FAIL, Severity.CRITICAL),
        check(CheckType.DNS_DMARC, CheckStatus.FAIL, Severity.CRITICAL),
        check(CheckType.DNS_DKIM, CheckStatus.FAIL, Severity.CRITICAL),
        check(CheckType.DNS_CAA, CheckStatus.FAIL, Severity.CRITICAL),
        check(CheckType.TLS_CERTIFICATE, CheckStatus.PASS),
    ]
    result = calculate_score(results)
    dns = next(c for c in result.categories if c.category is Category.DNS)
    assert dns.points <= dns.max_points


def test_warn_costs_less_than_fail() -> None:
    warn = calculate_score(
        replace(clean_results(), check(CheckType.DNS_SPF, CheckStatus.WARN, Severity.MEDIUM))
    )
    fail = calculate_score(
        replace(clean_results(), check(CheckType.DNS_SPF, CheckStatus.FAIL, Severity.MEDIUM))
    )
    assert warn.score < fail.score


def test_breakdown_is_serializable_and_explains_every_category() -> None:
    payload = calculate_score(clean_results()).to_dict()
    assert payload["score"] == 0
    assert len(payload["categories"]) == len(CATEGORY_WEIGHTS)
    for category in payload["categories"]:
        assert {"category", "display_name", "points", "max_points", "assessed"} <= set(category)
    assert sum(c["max_points"] for c in payload["categories"]) == 100


# --------------------------------------------------------------------- verdicts
def test_verdict_for_clean_vendor_makes_no_safety_claim() -> None:
    results = clean_results()
    verdict = build_verdict(calculate_score(results), results)
    text = f"{verdict.headline} {verdict.explanation}".lower()
    assert "no significant issues" in verdict.headline.lower()
    for forbidden in ("is safe", "is secure", "guarantee", "compliant", "certified"):
        assert forbidden not in text


def test_verdict_names_the_biggest_risk_and_the_next_action() -> None:
    results = replace(
        clean_results(),
        check(
            CheckType.TLS_CERTIFICATE,
            CheckStatus.FAIL,
            Severity.CRITICAL,
            title="Expired TLS certificate",
            summary="The vendor's TLS certificate has expired.",
            recommendation="Contact the vendor and ask them to renew the certificate.",
        ),
    )
    score = calculate_score(results)
    verdict = build_verdict(score, results)
    assert verdict.biggest_risk == "Expired TLS certificate"
    assert verdict.why_it_matters
    assert "renew" in verdict.recommended_action.lower()
    assert "High risk" in verdict.headline


def test_verdict_reports_incomplete_assessment() -> None:
    results = [
        check(ct, CheckStatus.ERROR, confidence=0.0)
        for ct in (CheckType.TLS_CERTIFICATE, CheckType.BREACH_HISTORY, CheckType.DNS_SPF)
    ]
    verdict = build_verdict(calculate_score(results), results)
    assert verdict.headline == "Assessment incomplete"
    assert verdict.biggest_risk is None


def test_verdict_states_coverage_when_a_provider_failed() -> None:
    results = replace(
        clean_results(), check(CheckType.INTERNET_EXPOSURE, CheckStatus.ERROR, confidence=0.0)
    )
    verdict = build_verdict(calculate_score(results), results)
    assert verdict.coverage_note is not None
    assert "not an indication that those areas are safe" in verdict.coverage_note


def test_every_verdict_carries_the_standard_disclaimer() -> None:
    for results in (clean_results(), [check(CheckType.DNS_SPF, CheckStatus.FAIL, Severity.MEDIUM)]):
        verdict = build_verdict(calculate_score(results), results)
        assert any("not legal, regulatory" in d for d in verdict.disclaimers)


def test_verdict_never_uses_absolute_language_on_a_bad_vendor() -> None:
    results = [
        check(CheckType.TLS_CERTIFICATE, CheckStatus.FAIL, Severity.CRITICAL),
        check(CheckType.BREACH_HISTORY, CheckStatus.FAIL, Severity.CRITICAL, confidence=0.95),
        check(CheckType.DNS_SPF, CheckStatus.FAIL, Severity.MEDIUM),
    ]
    verdict = build_verdict(calculate_score(results), results)
    text = f"{verdict.headline} {verdict.explanation} {verdict.recommended_action}".lower()
    for forbidden in ("this vendor is unsafe", "is insecure", "definitely", "guarantee"):
        assert forbidden not in text
    assert "signals associated with elevated security risk" in verdict.explanation
