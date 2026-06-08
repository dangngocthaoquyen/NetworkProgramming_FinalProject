"""Markdown report rendering for Phase 3 vulnerability results."""

from __future__ import annotations

from app.schemas.agent_result_schema import AgentResult
from app.schemas.enum_schema import EnumInput
from app.schemas.vuln_schema import Severity, VulnerabilityOutput


def render_markdown_report(
    output: VulnerabilityOutput,
    enum_input: EnumInput,
    agent_results: tuple[AgentResult, ...],
) -> str:
    """Render a structured Markdown report for an authorized scan."""

    lines = [
        f"# Phase 3 Vulnerability Report: {output.scan_id}",
        "",
        "## Executive Summary",
        "",
        (
            f"The authorized Phase 3 scan produced {output.summary.total} "
            "normalized findings."
        ),
        "",
        "## Scope",
        "",
        f"- Target label: {enum_input.target}",
        f"- Authorized hosts: {', '.join(str(host.ip) for host in enum_input.hosts)}",
        "- Public Internet scanning: blocked",
        "",
        "## Findings by Severity",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
        f"| Critical | {output.summary.critical} |",
        f"| High | {output.summary.high} |",
        f"| Medium | {output.summary.medium} |",
        f"| Low | {output.summary.low} |",
        f"| Info | {output.summary.info} |",
        "",
        "## Technical Details",
        "",
    ]

    if not output.findings:
        lines.append("No findings were produced.")
    for finding in output.findings:
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- CVE ID: {finding.cve_id or finding.finding_id}",
                f"- Host: {finding.host or 'N/A'}",
                f"- Port: {finding.port or 'N/A'}",
                f"- Severity: {finding.severity.value}",
                f"- CVSS: {finding.cvss if finding.cvss is not None else 'N/A'}",
                f"- Confidence: {finding.confidence:.2f}",
                f"- Risk score: {finding.risk_score:.2f}",
                f"- Source agents: {', '.join(finding.source_agents) or 'N/A'}",
                f"- Evidence: {finding.evidence}",
                "",
            ]
        )

    lines.extend(["## Remediation", ""])
    if not output.findings:
        lines.append("No remediation actions are required from this scan.")
    for finding in output.findings:
        lines.append(f"- **{finding.title}:** {finding.remediation}")

    lines.extend(["", "## Appendix", "", "### Agent Status", ""])
    lines.extend(
        f"- `{result.agent_name}`: {result.status.value}"
        + (f" - {result.message}" if result.message else "")
        for result in agent_results
    )
    lines.extend(
        [
            "",
            "### Methodology",
            "",
            "Findings were deduplicated by host, port, CVE ID, and title. Risk "
            "scores were calculated from CVSS and confidence, with a capped "
            "bonus for Nuclei confirmation.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"
