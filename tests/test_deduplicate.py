from app.merge.deduplicate import deduplicate_findings
from app.schemas.vuln_schema import Finding, Severity


def make_finding(source: str, evidence: str, confidence: float) -> Finding:
    return Finding(
        finding_id="CVE-2099-1234",
        cve_id="CVE-2099-1234",
        title="Shared CVE finding",
        host="192.168.1.10",
        port=443,
        source_agents=[source],
        severity=Severity.HIGH,
        cvss=8.0,
        confidence=confidence,
        evidence=evidence,
        remediation="Apply vendor remediation.",
        risk_score=0,
    )


def test_deduplicate_merges_sources_and_evidence():
    findings = [
        make_finding("cve_lookup_agent", "CVE database match.", 0.8),
        make_finding("nuclei_agent", "Nuclei confirmation.", 0.9),
    ]

    merged = deduplicate_findings(findings)

    assert len(merged) == 1
    assert merged[0].source_agents == ["cve_lookup_agent", "nuclei_agent"]
    assert "CVE database match." in merged[0].evidence
    assert "Nuclei confirmation." in merged[0].evidence
    assert merged[0].confidence == 0.9


def test_deduplicate_keeps_different_ports_separate():
    first = make_finding("cve_lookup_agent", "Port 443.", 0.8)
    second = make_finding("nuclei_agent", "Port 8443.", 0.8).model_copy(
        update={"port": 8443}
    )

    assert len(deduplicate_findings([first, second])) == 2
