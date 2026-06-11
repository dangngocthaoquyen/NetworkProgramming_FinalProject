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


def severity_from_cvss(cvss: float | None) -> Severity:
    """Map CVSS to the standard qualitative severity rating."""

    score = cvss or 0.0
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def severity_from_risk_score(risk_score: float) -> Severity:
    """Backward-compatible risk-score severity helper."""

    if risk_score >= 90:
        return Severity.CRITICAL
    if risk_score >= 70:
        return Severity.HIGH
    if risk_score >= 40:
        return Severity.MEDIUM
    return Severity.LOW


def score_finding(finding: Finding) -> Finding:
    """Return a finding with risk score and standard CVSS severity."""

    risk_score = calculate_risk_score(
        finding.cvss,
        finding.confidence,
        finding.source_agents,
    )
    return finding.model_copy(
        update={
            "risk_score": risk_score,
            "severity": severity_from_cvss(finding.cvss),
        }
    )
