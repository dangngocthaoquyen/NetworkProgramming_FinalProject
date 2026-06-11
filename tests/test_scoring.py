import pytest

from app.merge.scoring import (
    calculate_risk_score,
    score_finding,
    severity_from_cvss,
    severity_from_risk_score,
)
from app.schemas.vuln_schema import Finding, Severity


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (90, Severity.CRITICAL),
        (70, Severity.HIGH),
        (40, Severity.MEDIUM),
        (39.99, Severity.LOW),
    ],
)
def test_severity_thresholds(score: float, severity: Severity):
    assert severity_from_risk_score(score) is severity


def test_risk_score_formula_and_nuclei_bonus():
    assert calculate_risk_score(8.0, 0.8, ["cve_lookup_agent"]) == 64.0
    assert calculate_risk_score(8.0, 0.8, ["nuclei_agent"]) == 69.0
    assert calculate_risk_score(10.0, 1.0, ["nuclei_agent"]) == 100.0


@pytest.mark.parametrize(
    ("cvss", "severity"),
    [
        (10.0, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (8.9, Severity.HIGH),
        (7.0, Severity.HIGH),
        (6.9, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.9, Severity.LOW),
        (0.1, Severity.LOW),
        (0.0, Severity.INFO),
        (None, Severity.INFO),
    ],
)
def test_standard_cvss_severity_ranges(cvss: float | None, severity: Severity):
    assert severity_from_cvss(cvss) is severity


def test_score_finding_updates_score_and_severity():
    finding = Finding(
        finding_id="CVE-2099-1234",
        title="Scored finding",
        source_agents=["cve_lookup_agent"],
        severity=Severity.LOW,
        cvss=9.0,
        confidence=0.8,
        evidence="Evidence.",
        remediation="Remediation.",
        risk_score=0,
    )

    scored = score_finding(finding)

    assert scored.risk_score == 72.0
    assert scored.severity is Severity.CRITICAL
