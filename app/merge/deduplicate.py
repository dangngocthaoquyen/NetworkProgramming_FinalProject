"""Deduplicate and merge normalized vulnerability findings."""

from __future__ import annotations

from app.schemas.vuln_schema import Finding


FindingKey = tuple[str | None, int | None, str, str]


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings sharing location, canonical vulnerability ID, and source type."""

    merged: dict[FindingKey, Finding] = {}
    for finding in findings:
        key = (
            finding.host,
            finding.port,
            _canonical_vulnerability_id(finding),
            finding.source_type.value,
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding.model_copy(deep=True)
            continue

        source_agents = _unique(existing.source_agents + finding.source_agents)
        intel_sources = _unique(existing.intel_sources + finding.intel_sources)
        aliases = _unique(existing.aliases + finding.aliases)
        evidence = _unique(_evidence_parts(existing.evidence) + _evidence_parts(finding.evidence))
        remediations = _unique([existing.remediation, finding.remediation])
        references = _unique(existing.references + finding.references)
        match_methods = _unique(
            [value for value in (existing.match_method, finding.match_method) if value]
        )

        merged[key] = existing.model_copy(
            update={
                "source_agents": source_agents,
                "intel_sources": intel_sources,
                "aliases": aliases,
                "evidence": "\n".join(evidence),
                "references": references,
                "remediation": "\n".join(remediations),
                "match_method": "; ".join(match_methods) if match_methods else None,
                "cvss": max(
                    value
                    for value in (existing.cvss, finding.cvss)
                    if value is not None
                )
                if existing.cvss is not None or finding.cvss is not None
                else None,
                "confidence": max(existing.confidence, finding.confidence),
                "validation_required": existing.validation_required
                and finding.validation_required,
            }
        )

    return list(merged.values())


def _evidence_parts(evidence: str) -> list[str]:
    return [part for part in evidence.splitlines() if part]


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _canonical_vulnerability_id(finding: Finding) -> str:
    for value in [finding.cve_id, *finding.aliases]:
        if value and value.upper().startswith("CVE-"):
            return value.upper()

    if finding.cve_id:
        return finding.cve_id
    return f"{finding.finding_id}|{finding.title.casefold()}"
