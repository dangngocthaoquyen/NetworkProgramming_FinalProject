"""Risk scoring and severity normalization for merged findings."""

from __future__ import annotations

from app.schemas.vuln_schema import Finding, Severity


NUCLEI_CONFIRMATION_BONUS = 5.0
MAX_RISK_SCORE = 100.0


def calculate_risk_score(
    cvss: float | None,
    confidence: float,
    source_agents: list[str] | tuple[str, ...] = (),
) -> float:
    """Calculate normalized risk score using CVSS, confidence, and confirmation."""

    score = (cvss or 0.0) * 10 * confidence
    if any("nuclei" in source.casefold() for source in source_agents):
        score += NUCLEI_CONFIRMATION_BONUS
    return round(min(score, MAX_RISK_SCORE), 2)


def severity_from_risk_score(risk_score: float) -> Severity:
    """Map a normalized risk score to its severity band."""

    if risk_score >= 90:
        return Severity.CRITICAL
    if risk_score >= 70:
        return Severity.HIGH
    if risk_score >= 40:
        return Severity.MEDIUM
    return Severity.LOW


def score_finding(finding: Finding) -> Finding:
    """Return a copy of a finding with normalized risk score and severity."""

    risk_score = calculate_risk_score(
        finding.cvss,
        finding.confidence,
        finding.source_agents,
    )
    return finding.model_copy(
        update={
            "risk_score": risk_score,
            "severity": severity_from_risk_score(risk_score),
        }
    )
