"""Offline CVE lookup agent backed by a local mock database."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.agent_result_schema import AgentResult, AgentStatus
from app.schemas.enum_schema import EnumInput, OperatingSystem, Port
from app.schemas.vuln_schema import Finding, Severity, SourceType


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
    source_type: SourceType = SourceType.SERVICE
    product: str | None = Field(default=None, min_length=1)
    match_type: MatchType
    version: str | None = None
    version_range: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    kernel: str | None = None
    build: str | None = None
    cvss: float = Field(ge=0, le=10)
    title: str = Field(min_length=1)
    remediation: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_lookup_fields(self) -> CveRecord:
        if self.source_type is SourceType.SERVICE and self.product is None:
            raise ValueError("Service CVE records require product")
        if self.source_type is SourceType.OS and self.os_name is None:
            raise ValueError("OS CVE records require os_name")
        return self


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
                    if record.source_type is not SourceType.SERVICE:
                        continue
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
                            source_type=SourceType.SERVICE,
                            severity=self._severity_for_cvss(record.cvss),
                            cvss=record.cvss,
                            confidence=confidence,
                            evidence=self._evidence(str(host.ip), port, record),
                            remediation=record.remediation,
                            risk_score=round(record.cvss * confidence, 2),
                        )
                    )

            if host.os is not None:
                for record in database.records:
                    if record.source_type is not SourceType.OS:
                        continue
                    confidence = self._os_match_confidence(host.os, record)
                    if confidence is None or record.cvss < MINIMUM_CVSS:
                        continue
                    confidence = self._combine_os_confidence(
                        confidence, host.os.confidence
                    )

                    findings.append(
                        Finding(
                            finding_id=record.cve_id,
                            cve_id=record.cve_id,
                            title=f"{record.cve_id}: {record.title}",
                            host=str(host.ip),
                            port=None,
                            source_agents=[self.agent_name],
                            source_type=SourceType.OS,
                            severity=self._severity_for_cvss(record.cvss),
                            cvss=record.cvss,
                            confidence=confidence,
                            evidence=self._os_evidence(str(host.ip), host.os, record),
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
            message=f"Found {len(findings)} high-severity offline CVE matches.",
            data={"findings": [finding.model_dump(mode="json") for finding in findings]},
        )

    def _load_database(self) -> CveMockDatabase:
        payload = json.loads(self.db_path.read_text(encoding="utf-8"))
        return CveMockDatabase.model_validate(payload)

    @staticmethod
    def _match_confidence(port: Port, record: CveRecord) -> float | None:
        product = port.product or port.service
        if record.product is None or product.casefold() != record.product.casefold():
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
    def _os_match_confidence(
        operating_system: OperatingSystem, record: CveRecord
    ) -> float | None:
        if (
            operating_system.name is None
            or record.os_name is None
            or CveLookupAgent._normalized_os_name(operating_system)
            != " ".join(record.os_name.casefold().split())
        ):
            return None

        expected_fields = (
            (record.os_version, operating_system.version),
            (record.kernel, operating_system.kernel),
            (record.build, operating_system.build),
        )
        for expected, actual in expected_fields:
            if expected is not None and (
                actual is None or actual.casefold() != expected.casefold()
            ):
                return None

        return 0.95

    @staticmethod
    def _normalized_os_name(operating_system: OperatingSystem) -> str:
        name = " ".join((operating_system.name or "").casefold().split())
        if name == "windows" and operating_system.version:
            return f"{name} {operating_system.version.casefold()}"
        return name

    @staticmethod
    def _combine_os_confidence(
        local_match_confidence: float, fingerprint_confidence: float | None
    ) -> float:
        if fingerprint_confidence is None:
            return local_match_confidence
        return round(local_match_confidence * (fingerprint_confidence / 100), 3)

    @staticmethod
    def _severity_for_cvss(cvss: float) -> Severity:
        return Severity.CRITICAL if cvss >= 9.0 else Severity.HIGH

    @staticmethod
    def _evidence(host_ip: str, port: Port, record: CveRecord) -> str:
        product = port.product or port.service
        version = port.version or "unknown"
        evidence = (
            f"Offline mock DB matched {product} {version} on "
            f"{host_ip}:{port.port}/{port.protocol} using {record.match_type.value} match."
        )
        if port.cpe:
            evidence += f" Enumerated CPE: {', '.join(port.cpe)}."
        return evidence

    @staticmethod
    def _os_evidence(
        host_ip: str, operating_system: OperatingSystem, record: CveRecord
    ) -> str:
        matched = [
            f"name={operating_system.name or 'unknown'}",
            f"version={operating_system.version or 'unknown'}",
            f"kernel={operating_system.kernel or 'unknown'}",
            f"build={operating_system.build or 'unknown'}",
        ]
        evidence = (
            f"Offline mock DB matched OS fingerprint on {host_ip}: "
            f"{', '.join(matched)} using {record.match_type.value} match."
        )
        if operating_system.cpe:
            evidence += f" Enumerated OS CPE: {', '.join(operating_system.cpe)}."
        return evidence
