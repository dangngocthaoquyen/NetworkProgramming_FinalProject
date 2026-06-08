"""Offline CVE lookup agent backed by a local mock database."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.agent_result_schema import AgentResult, AgentStatus
from app.schemas.enum_schema import EnumInput, Port
from app.schemas.vuln_schema import Finding, Severity


DEFAULT_CVE_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "cve_mock_db.json"
MINIMUM_CVSS = 7.0


class MatchType(StrEnum):
    """Supported local CVE matching strategies."""

    EXACT = "exact"
    RANGE = "range"
    PRODUCT = "product"


class CveRecord(BaseModel):
    """Validated entry from the local mock CVE database."""

    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    product: str = Field(min_length=1)
    match_type: MatchType
    version: str | None = None
    version_range: str | None = None
    cvss: float = Field(ge=0, le=10)
    title: str = Field(min_length=1)
    remediation: str = Field(min_length=1)


class CveMockDatabase(BaseModel):
    """Validated local CVE database document."""

    model_config = ConfigDict(extra="forbid")

    records: list[CveRecord]


class CveLookupAgent:
    """Match enumerated products against an offline mock CVE database."""

    agent_name = "cve_lookup_agent"

    def __init__(self, db_path: str | Path = DEFAULT_CVE_DB_PATH) -> None:
        self.db_path = Path(db_path)

    def lookup(self, enum_input: EnumInput) -> list[Finding]:
        """Return high-severity local CVE matches for a validated enum object."""

        if not isinstance(enum_input, EnumInput):
            raise TypeError("CveLookupAgent requires a validated EnumInput object")

        database = self._load_database()
        findings: list[Finding] = []

        for host in enum_input.hosts:
            for port in host.ports:
                for record in database.records:
                    confidence = self._match_confidence(port, record)
                    if confidence is None or record.cvss < MINIMUM_CVSS:
                        continue

                    findings.append(
                        Finding(
                            finding_id=record.cve_id,
                            cve_id=record.cve_id,
                            title=f"{record.cve_id}: {record.title}",
                            host=str(host.ip),
                            port=port.port,
                            source_agents=[self.agent_name],
                            severity=self._severity_for_cvss(record.cvss),
                            cvss=record.cvss,
                            confidence=confidence,
                            evidence=self._evidence(str(host.ip), port, record),
                            remediation=record.remediation,
                            risk_score=round(record.cvss * confidence, 2),
                        )
                    )

        return findings

    def run(self, enum_input: EnumInput) -> AgentResult:
        """Run lookup without allowing agent errors to crash the pipeline."""

        try:
            findings = self.lookup(enum_input)
        except Exception as exc:
            return AgentResult(
                agent_name=self.agent_name,
                scan_id=enum_input.scan_id,
                status=AgentStatus.FAILED,
                message="Offline CVE lookup failed.",
                errors=[str(exc)],
            )

        return AgentResult(
            agent_name=self.agent_name,
            scan_id=enum_input.scan_id,
            status=AgentStatus.SUCCESS,
            message=f"Found {len(findings)} high-severity local CVE matches.",
            data={"findings": [finding.model_dump(mode="json") for finding in findings]},
        )

    def _load_database(self) -> CveMockDatabase:
        payload = json.loads(self.db_path.read_text(encoding="utf-8"))
        return CveMockDatabase.model_validate(payload)

    @staticmethod
    def _match_confidence(port: Port, record: CveRecord) -> float | None:
        product = port.product or port.service
        if product.casefold() != record.product.casefold():
            return None

        if record.match_type is MatchType.PRODUCT:
            return 0.40

        if port.version is None:
            return None

        if record.match_type is MatchType.EXACT:
            return 0.95 if port.version.casefold() == (record.version or "").casefold() else None

        if record.match_type is MatchType.RANGE and record.version_range:
            try:
                return (
                    0.80
                    if Version(port.version) in SpecifierSet(record.version_range)
                    else None
                )
            except (InvalidSpecifier, InvalidVersion):
                return None

        return None

    @staticmethod
    def _severity_for_cvss(cvss: float) -> Severity:
        return Severity.CRITICAL if cvss >= 9.0 else Severity.HIGH

    @staticmethod
    def _evidence(host_ip: str, port: Port, record: CveRecord) -> str:
        product = port.product or port.service
        version = port.version or "unknown"
        return (
            f"Offline mock DB matched {product} {version} on "
            f"{host_ip}:{port.port}/{port.protocol} using {record.match_type.value} match."
        )
