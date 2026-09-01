"""Plain-English risk verdicts.

Zentra's customers are founders and operators, not security analysts. Every
verdict answers three questions in ordinary language:

1. What is the biggest risk?
2. Why does it matter?
3. What should I do next?

Language rules (see docs/risk-scoring.md):

* Never assert that a vendor "is insecure" or "is safe". Zentra observes
  signals from public sources; it does not audit the vendor.
* Never make a legal, regulatory or certification claim.
* Always say when the assessment is incomplete.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from zentra.scanners.base import CheckResult, CheckType
from zentra.scoring.config import RiskLevel
from zentra.scoring.engine import ScoreResult, rank_problems

_LEVEL_OPENER: dict[RiskLevel, str] = {
    RiskLevel.LOW: "Low risk",
    RiskLevel.MEDIUM: "Medium risk",
    RiskLevel.HIGH: "High risk",
    RiskLevel.CRITICAL: "Critical risk",
}

_WHY_IT_MATTERS: dict[str, str] = {
    CheckType.TLS_CERTIFICATE.value: (
        "Certificate problems break the trust between your staff and the vendor's service, "
        "and they are a common precursor to interception or a service outage."
    ),
    CheckType.TLS_CONFIGURATION.value: (
        "Outdated encryption settings make it easier for an attacker positioned on the network "
        "to read or tamper with traffic to this vendor."
    ),
    CheckType.BREACH_HISTORY.value: (
        "A vendor that has been breached before may still hold your data, and credentials "
        "exposed in a breach are frequently reused against other systems."
    ),
    CheckType.INTERNET_EXPOSURE.value: (
        "Services that face the public internet are the parts of a vendor most often targeted, "
        "and administrative interfaces should rarely be reachable this way."
    ),
    CheckType.CVE_EXPOSURE.value: (
        "Published vulnerabilities give attackers a known route in if the vendor has not "
        "applied the corresponding patches."
    ),
    CheckType.DNS_SPF.value: (
        "Without email authentication, someone can send convincing phishing email that appears "
        "to come from this vendor to your staff or your customers."
    ),
    CheckType.DNS_DMARC.value: (
        "Without an enforced DMARC policy, spoofed email claiming to be from this vendor is "
        "still delivered to inboxes."
    ),
    CheckType.HTTP_SECURITY_HEADERS.value: (
        "Browser security headers limit the damage of common web attacks against anyone using "
        "the vendor's site."
    ),
    CheckType.DNS_CAA.value: (
        "Without a CAA record, any certificate authority can issue certificates for the "
        "vendor's domain."
    ),
}

_LEVEL_ACTION: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: (
        "Treat this as urgent: raise it with the vendor now and consider pausing any new data "
        "sharing until you have a response."
    ),
    RiskLevel.HIGH: (
        "Raise this with the vendor and ask for a remediation date. Record their answer against "
        "this vendor for your next review."
    ),
    RiskLevel.MEDIUM: (
        "Add this to your next vendor review and ask the vendor about it at renewal."
    ),
    RiskLevel.LOW: (
        "No action needed. Zentra will keep monitoring and will alert you if this changes."
    ),
}


@dataclass
class Verdict:
    headline: str
    explanation: str
    biggest_risk: str | None
    why_it_matters: str | None
    recommended_action: str
    coverage_note: str | None = None
    disclaimers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "headline": self.headline,
            "explanation": self.explanation,
            "biggest_risk": self.biggest_risk,
            "why_it_matters": self.why_it_matters,
            "recommended_action": self.recommended_action,
            "coverage_note": self.coverage_note,
            "disclaimers": self.disclaimers,
        }


STANDARD_DISCLAIMER = (
    "Zentra's risk scores are informational assessments based on signals from publicly "
    "available sources. They are not an audit of the vendor and are not legal, regulatory or "
    "certification advice."
)


def build_verdict(score_result: ScoreResult, results: list[CheckResult]) -> Verdict:
    """Compose the customer-facing explanation for a scored scan."""
    level = score_result.risk_level or RiskLevel.MEDIUM
    opener = _LEVEL_OPENER[level]
    problems = rank_problems(results)

    unassessed = [c for c in score_result.categories if not c.assessed]
    coverage_note = _coverage_note(score_result, unassessed)

    disclaimers = [STANDARD_DISCLAIMER]

    if score_result.inconclusive:
        return Verdict(
            headline="Assessment incomplete",
            explanation=(
                "Zentra could not complete enough checks to produce a reliable risk score for "
                "this vendor. This usually means the data sources were temporarily "
                "unavailable, or the domain does not host the services we assess."
            ),
            biggest_risk=None,
            why_it_matters=None,
            recommended_action=(
                "Re-run the scan shortly. If it keeps failing, confirm the vendor's domain is "
                "correct."
            ),
            coverage_note=coverage_note,
            disclaimers=disclaimers,
        )

    if not problems:
        explanation = (
            "Zentra did not detect any signals associated with elevated security risk for this "
            "vendor across the checks that completed."
        )
        if coverage_note:
            explanation += " " + coverage_note
        return Verdict(
            headline=f"{opener}: no significant issues detected",
            explanation=explanation,
            biggest_risk=None,
            why_it_matters=None,
            recommended_action=_LEVEL_ACTION[level],
            coverage_note=coverage_note,
            disclaimers=disclaimers,
        )

    primary = problems[0]
    biggest = primary.title or primary.summary
    why = _WHY_IT_MATTERS.get(primary.check_type.value)
    action = primary.recommendation or _LEVEL_ACTION[level]

    others = problems[1:3]
    summary_bits = [primary.summary.rstrip(".")]
    for other in others:
        summary_bits.append(other.summary.rstrip(".").lower())

    if len(problems) == 1:
        detail = f"{summary_bits[0]}."
    elif len(problems) <= 3:
        detail = "; ".join(summary_bits) + "."
    else:
        detail = (
            "; ".join(summary_bits) + f"; and {len(problems) - len(summary_bits)} further issue(s)."
        )

    explanation = f"Zentra detected signals associated with elevated security risk. {detail}"
    if primary.confidence < 0.6:
        explanation += (
            " This finding is based on a lower-confidence signal and is worth confirming with "
            "the vendor."
        )
    if coverage_note:
        explanation += " " + coverage_note

    headline = f"{opener}: {(primary.title or primary.summary).rstrip('.')}"
    return Verdict(
        headline=headline[:200],
        explanation=explanation,
        biggest_risk=biggest,
        why_it_matters=why,
        recommended_action=action,
        coverage_note=coverage_note,
        disclaimers=disclaimers,
    )


def _coverage_note(score_result: ScoreResult, unassessed: list[Any]) -> str | None:
    if not unassessed:
        return None
    unavailable = [c for c in unassessed if c.status == "unavailable"]
    names = ", ".join(c.display_name.lower() for c in unassessed)
    percent = round(score_result.coverage * 100)
    if unavailable:
        return (
            f"This assessment covers {percent}% of Zentra's checks: {names} could not be "
            "assessed because a data source was unavailable. That is not an indication that "
            "those areas are safe."
        )
    return (
        f"This assessment covers {percent}% of Zentra's checks; {names} could not be assessed "
        "for this domain."
    )
