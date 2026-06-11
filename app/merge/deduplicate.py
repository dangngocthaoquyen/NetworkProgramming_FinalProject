"""Deduplicate and merge normalized vulnerability findings."""

from __future__ import annotations

from app.schemas.vuln_schema import Finding


FindingKey = tuple[str | None, int | None, str, str, str]


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings sharing host, port, CVE identifier, title, and source type."""

    merged: dict[FindingKey, Finding] = {}
    for finding in findings:
        key = (
            finding.host,
            finding.port,
            finding.cve_id or finding.finding_id,
            finding.title.casefold(),
            finding.source_type.value,
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding.model_copy(deep=True)
            continue

        source_agents = _unique(existing.source_agents + finding.source_agents)
        evidence = _unique(_evidence_parts(existing.evidence) + _evidence_parts(finding.evidence))
        remediations = _unique([existing.remediation, finding.remediation])

        merged[key] = existing.model_copy(
            update={
                "source_agents": source_agents,
                "evidence": "\n".join(evidence),
                "remediation": "\n".join(remediations),
                "cvss": max(
                    value
                    for value in (existing.cvss, finding.cvss)
                    if value is not None
                )
                if existing.cvss is not None or finding.cvss is not None
                else None,
                "confidence": max(existing.confidence, finding.confidence),
            }
        )

    return list(merged.values())


def _evidence_parts(evidence: str) -> list[str]:
    return [part for part in evidence.splitlines() if part]


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
