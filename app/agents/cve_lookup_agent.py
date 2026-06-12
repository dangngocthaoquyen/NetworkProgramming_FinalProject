"""CVE lookup agent with mock, live NVD, and fallback modes."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from enum import StrEnum
from pathlib import Path
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field, model_validator
import yaml

from app.schemas.agent_result_schema import AgentResult, AgentStatus
from app.schemas.enum_schema import EnumInput, OperatingSystem, Port
from app.schemas.vuln_schema import Finding, Severity, SourceType
from app.tools.nvd_client import (
    NvdClient,
    NvdClientError,
    english_description,
    extract_cvss,
    normalize_cpe23,
    references_from_nvd,
)
from app.tools.osv_client import (
    OsvClient,
    OsvClientError,
    aliases_from_osv,
    extract_cvss_from_osv,
    preferred_cve_from_osv,
    references_from_osv,
    summary_from_osv,
)


DEFAULT_CVE_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "cve_mock_db.json"
DEFAULT_CONFIG_PATH = Path("config.yaml")
LOGGER = logging.getLogger(__name__)


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
    references: list[str] = Field(default_factory=list)
    origin: str | None = None

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


class OsvPackageMapping(BaseModel):
    """Explicit service-to-package mapping used for cautious OSV lookups."""

    model_config = ConfigDict(extra="forbid")

    product: str | None = Field(default=None, min_length=1)
    service: str | None = Field(default=None, min_length=1)
    cpe_prefix: str | None = Field(default=None, min_length=1)
    ecosystem: str = Field(min_length=1)
    package: str = Field(min_length=1)
    notes: str | None = None

    @model_validator(mode="after")
    def validate_selector(self) -> OsvPackageMapping:
        if not any((self.product, self.service, self.cpe_prefix)):
            raise ValueError(
                "OSV package mappings require product, service, or cpe_prefix matching"
            )
        return self


class ResolvedOsvQuery(BaseModel):
    """A validated OSV query resolved from an explicit config mapping."""

    model_config = ConfigDict(extra="forbid")

    host_ip: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    protocol: str = Field(min_length=1)
    product: str = Field(min_length=1)
    version: str = Field(min_length=1)
    ecosystem: str = Field(min_length=1)
    package: str = Field(min_length=1)
    notes: str | None = None

    def query_payload(self) -> dict[str, Any]:
        return {
            "package": {
                "ecosystem": self.ecosystem,
                "name": self.package,
            },
            "version": self.version,
        }


class CveLookupAgent:
    """Match enumerated products against mock or live CVE intelligence."""

    agent_name = "cve_lookup_agent"

    def __init__(
        self,
        db_path: str | Path = DEFAULT_CVE_DB_PATH,
        *,
        config_path: str | Path = DEFAULT_CONFIG_PATH,
        nvd_client: NvdClient | None = None,
        osv_client: OsvClient | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.config_path = Path(config_path)
        self._nvd_client = nvd_client
        self._osv_client = osv_client

    def lookup(self, enum_input: EnumInput) -> list[Finding]:
        """Return high-severity local CVE matches for a validated enum object."""

        if not isinstance(enum_input, EnumInput):
            raise TypeError("CveLookupAgent requires a validated EnumInput object")

        config = self._load_lookup_config()
        findings = self._service_findings(enum_input, config)
        if config["source"] != "mock" and config["osv"]["enabled"]:
            findings.extend(self._service_findings_from_osv(enum_input, config, findings))
        if config["source"] != "nvd_live":
            findings.extend(self._os_findings_from_mock(enum_input, config))
        return findings

    def _service_findings(
        self, enum_input: EnumInput, config: dict[str, Any]
    ) -> list[Finding]:
        source = config["source"]
        if source == "mock":
            return self._service_findings_from_mock(enum_input, config)
        if source == "nvd_live":
            return self._service_findings_from_nvd(enum_input, config, fallback_to_mock=False)
        if source == "auto":
            if os.getenv("NVD_API_KEY"):
                try:
                    return self._service_findings_from_nvd(
                        enum_input, config, fallback_to_mock=True
                    )
                except NvdClientError:
                    return self._service_findings_from_mock(enum_input, config)
            cached = self._service_findings_from_cache(enum_input, config)
            return cached or self._service_findings_from_mock(enum_input, config)
        raise ValueError(f"Unsupported cve_lookup.source: {source}")

    def _service_findings_from_mock(
        self, enum_input: EnumInput, config: dict[str, Any]
    ) -> list[Finding]:
        database = self._load_database()
        findings: list[Finding] = []
        minimum_cvss = float(config["min_cvss"])

        for host in enum_input.hosts:
            for port in host.ports:
                for record in database.records:
                    if record.source_type is not SourceType.SERVICE:
                        continue
                    confidence = self._match_confidence(port, record)
                    if confidence is None or record.cvss < minimum_cvss:
                        continue

                    findings.append(
                        Finding(
                            finding_id=record.cve_id,
                            cve_id=record.cve_id,
                            aliases=[],
                            title=f"{record.cve_id}: {record.title}",
                            host=str(host.ip),
                            port=port.port,
                            source_agents=[self.agent_name],
                            intel_sources=["mock"],
                            source_type=SourceType.SERVICE,
                            match_method=f"mock-{record.match_type.value}",
                            severity=self._severity_for_cvss(record.cvss),
                            cvss=record.cvss,
                            confidence=confidence,
                            evidence=self._evidence(str(host.ip), port, record),
                            references=record.references,
                            remediation=record.remediation,
                            risk_score=round(record.cvss * confidence, 2),
                        )
                    )
        return findings

    def _os_findings_from_mock(
        self, enum_input: EnumInput, config: dict[str, Any]
    ) -> list[Finding]:
        database = self._load_database()
        findings: list[Finding] = []
        minimum_cvss = float(config["min_cvss"])
        for host in enum_input.hosts:
            if host.os is None:
                continue
            for record in database.records:
                if record.source_type is not SourceType.OS:
                    continue
                confidence = self._os_match_confidence(host.os, record)
                if confidence is None or record.cvss < minimum_cvss:
                    continue
                confidence = self._combine_os_confidence(confidence, host.os.confidence)
                findings.append(
                    Finding(
                        finding_id=record.cve_id,
                        cve_id=record.cve_id,
                        aliases=[],
                        title=f"{record.cve_id}: {record.title}",
                        host=str(host.ip),
                        port=None,
                        source_agents=[self.agent_name],
                        intel_sources=["mock"],
                        source_type=SourceType.OS,
                        match_method=f"mock-{record.match_type.value}",
                        severity=self._severity_for_cvss(record.cvss),
                        cvss=record.cvss,
                        confidence=confidence,
                        evidence=self._os_evidence(str(host.ip), host.os, record),
                        references=record.references,
                        remediation=record.remediation,
                        risk_score=round(record.cvss * confidence, 2),
                    )
                )
        return findings

    def _service_findings_from_cache(
        self, enum_input: EnumInput, config: dict[str, Any]
    ) -> list[Finding]:
        client = self._nvd(config)
        allow_range_matches = bool(config["nvd"]["allow_range_matches"])
        findings: list[Finding] = []
        for host in enum_input.hosts:
            for port in host.ports:
                payload, confidence, query_label = self._cached_payload_for_port(client, port)
                if payload is None:
                    continue
                findings.extend(
                    self._nvd_payload_to_findings(
                        str(host.ip),
                        port,
                        payload,
                        query_label=query_label,
                        confidence=confidence,
                        minimum_cvss=float(config["min_cvss"]),
                        allow_range_matches=allow_range_matches,
                    )
                )
        return findings

    def _service_findings_from_nvd(
        self,
        enum_input: EnumInput,
        config: dict[str, Any],
        *,
        fallback_to_mock: bool,
    ) -> list[Finding]:
        client = self._nvd(config)
        allow_range_matches = bool(config["nvd"]["allow_range_matches"])
        findings: list[Finding] = []
        live_error: NvdClientError | None = None
        for host in enum_input.hosts:
            for port in host.ports:
                try:
                    payload, confidence, query_label = self._live_payload_for_port(client, port)
                except NvdClientError as exc:
                    live_error = exc
                    if fallback_to_mock:
                        continue
                    raise
                if payload is None:
                    continue
                findings.extend(
                    self._nvd_payload_to_findings(
                        str(host.ip),
                        port,
                        payload,
                        query_label=query_label,
                        confidence=confidence,
                        minimum_cvss=float(config["min_cvss"]),
                        allow_range_matches=allow_range_matches,
                    )
                )
        if live_error is not None and fallback_to_mock:
            findings.extend(self._service_findings_from_mock(enum_input, config))
        if findings or not fallback_to_mock:
            return findings
        return findings

    def _service_findings_from_osv(
        self,
        enum_input: EnumInput,
        config: dict[str, Any],
        baseline_findings: list[Finding],
    ) -> list[Finding]:
        osv_config = config["osv"]
        resolved_queries = self._resolve_osv_queries(enum_input, osv_config)
        if not resolved_queries:
            return []

        client = self._osv(config)
        findings: list[Finding] = []
        nvd_by_cve = {
            finding.cve_id.upper(): finding
            for finding in baseline_findings
            if finding.cve_id and "nvd" in finding.intel_sources
        }

        batch_size = int(osv_config["max_batch_size"])
        for index in range(0, len(resolved_queries), batch_size):
            chunk = resolved_queries[index : index + batch_size]
            try:
                results = client.query_batch([item.query_payload() for item in chunk])
            except OsvClientError as exc:
                LOGGER.debug("OSV querybatch failed for %d mapped services: %s", len(chunk), exc)
                continue
            if len(results) != len(chunk):
                LOGGER.debug(
                    "OSV querybatch returned %d results for %d queries; skipping the mismatched batch.",
                    len(results),
                    len(chunk),
                )
                continue

            for resolved, result in zip(chunk, results, strict=True):
                if not isinstance(result, dict):
                    continue
                findings.extend(
                    self._osv_result_to_findings(
                        resolved,
                        result,
                        client=client,
                        minimum_cvss=float(config["min_cvss"]),
                        nvd_by_cve=nvd_by_cve,
                    )
                )

        return findings

    async def run(self, enum_input: EnumInput) -> AgentResult:
        """Run lookup without allowing agent errors to crash the pipeline."""

        try:
            await asyncio.sleep(0)
            findings = self.lookup(enum_input)
        except Exception as exc:
            return AgentResult(
                agent_name=self.agent_name,
                scan_id=enum_input.scan_id,
                status=AgentStatus.FAILED,
                message="CVE lookup failed.",
                errors=[str(exc)],
            )

        return AgentResult(
            agent_name=self.agent_name,
            scan_id=enum_input.scan_id,
            status=AgentStatus.SUCCESS,
            message=f"Found {len(findings)} CVE intelligence matches at or above the configured CVSS threshold.",
            data={"findings": [finding.model_dump(mode="json") for finding in findings]},
        )

    def _load_database(self) -> CveMockDatabase:
        payload = json.loads(self.db_path.read_text(encoding="utf-8"))
        return CveMockDatabase.model_validate(payload)

    def _load_lookup_config(self) -> dict[str, Any]:
        config = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        lookup = config.get("cve_lookup", {}) if isinstance(config, dict) else {}
        if not isinstance(lookup, dict):
            raise ValueError("config.yaml cve_lookup must be a mapping")

        source = lookup.get("source", "auto")
        if source not in {"mock", "nvd_live", "auto"}:
            raise ValueError("cve_lookup.source must be mock, nvd_live, or auto")

        min_cvss = float(lookup.get("min_cvss", 7.0))
        nvd = lookup.get("nvd", {})
        if not isinstance(nvd, dict):
            raise ValueError("cve_lookup.nvd must be a mapping")
        osv = lookup.get("osv", {})
        if not isinstance(osv, dict):
            raise ValueError("cve_lookup.osv must be a mapping")

        package_mappings = osv.get("package_mappings", [])
        if not isinstance(package_mappings, list):
            raise ValueError("cve_lookup.osv.package_mappings must be a list")

        return {
            "source": source,
            "min_cvss": min_cvss,
            "nvd": {
                "cache_dir": nvd.get("cache_dir", "data/cache/nvd"),
                "use_cache": bool(nvd.get("use_cache", True)),
                "timeout_seconds": float(nvd.get("timeout_seconds", 20.0)),
                "allow_range_matches": bool(nvd.get("allow_range_matches", False)),
            },
            "osv": {
                "enabled": bool(osv.get("enabled", False)),
                "base_url": str(osv.get("base_url", "https://api.osv.dev/v1")),
                "cache_dir": str(osv.get("cache_dir", "data/cache/osv")),
                "use_cache": bool(osv.get("use_cache", True)),
                "timeout_seconds": float(osv.get("timeout_seconds", 15.0)),
                "max_batch_size": max(1, int(osv.get("max_batch_size", 20))),
                "max_retries": max(0, int(osv.get("max_retries", 2))),
                "enabled_for_package_ecosystems": [
                    str(item)
                    for item in osv.get("enabled_for_package_ecosystems", [])
                    if str(item)
                ],
                "package_mappings": [
                    OsvPackageMapping.model_validate(item) for item in package_mappings
                ],
            },
        }

    def _nvd(self, config: dict[str, Any]) -> NvdClient:
        if self._nvd_client is not None:
            return self._nvd_client
        nvd = config["nvd"]
        self._nvd_client = NvdClient(
            cache_dir=nvd["cache_dir"],
            use_cache=nvd["use_cache"],
            timeout_seconds=nvd["timeout_seconds"],
        )
        return self._nvd_client

    def _osv(self, config: dict[str, Any]) -> OsvClient:
        if self._osv_client is not None:
            return self._osv_client
        osv = config["osv"]
        self._osv_client = OsvClient(
            base_url=osv["base_url"],
            cache_dir=osv["cache_dir"],
            use_cache=osv["use_cache"],
            timeout_seconds=osv["timeout_seconds"],
            max_retries=osv["max_retries"],
        )
        return self._osv_client

    def _live_payload_for_port(
        self, client: NvdClient, port: Port
    ) -> tuple[dict[str, Any] | None, float, str]:
        for cpe in port.cpe:
            normalized = normalize_cpe23(cpe)
            if normalized is None:
                continue
            payload = client.search_cves(cpe_name=normalized)
            return payload, 0.95, f"cpeName={normalized}"

        keyword = self._keyword_for_port(port)
        if keyword is None:
            return None, 0.0, ""
        payload = client.search_cves(keyword_search=keyword)
        return payload, 0.75, f"keywordSearch={keyword}"

    def _cached_payload_for_port(
        self, client: NvdClient, port: Port
    ) -> tuple[dict[str, Any] | None, float, str]:
        for cpe in port.cpe:
            normalized = normalize_cpe23(cpe)
            if normalized is None:
                continue
            payload = client.load_cached(cpe_name=normalized)
            if payload is not None:
                return payload, 0.95, f"cpeName={normalized}"

        keyword = self._keyword_for_port(port)
        if keyword is None:
            return None, 0.0, ""
        payload = client.load_cached(keyword_search=keyword)
        if payload is not None:
            return payload, 0.75, f"keywordSearch={keyword}"
        return None, 0.0, ""

    def _resolve_osv_queries(
        self,
        enum_input: EnumInput,
        osv_config: dict[str, Any],
    ) -> list[ResolvedOsvQuery]:
        mappings: list[OsvPackageMapping] = osv_config["package_mappings"]
        if not mappings:
            LOGGER.debug("OSV enabled but no package_mappings were configured; skipping OSV lookup.")
            return []

        enabled_ecosystems = {
            value.casefold() for value in osv_config["enabled_for_package_ecosystems"]
        }
        resolved: list[ResolvedOsvQuery] = []

        for host in enum_input.hosts:
            for port in host.ports:
                if not port.version:
                    LOGGER.debug(
                        "Skipping OSV lookup for %s:%s because the service has no version.",
                        host.ip,
                        port.port,
                    )
                    continue

                matches = [
                    mapping
                    for mapping in mappings
                    if self._mapping_matches_port(mapping, port)
                    and (
                        not enabled_ecosystems
                        or mapping.ecosystem.casefold() in enabled_ecosystems
                    )
                ]
                if not matches:
                    LOGGER.debug(
                        "Skipping OSV lookup for %s:%s %s because no explicit package mapping matched.",
                        host.ip,
                        port.port,
                        port.product or port.service,
                    )
                    continue

                for mapping in matches:
                    resolved.append(
                        ResolvedOsvQuery(
                            host_ip=str(host.ip),
                            port=port.port,
                            protocol=port.protocol,
                            product=port.product or port.service,
                            version=port.version,
                            ecosystem=mapping.ecosystem,
                            package=mapping.package,
                            notes=mapping.notes,
                        )
                    )
        return resolved

    @staticmethod
    def _mapping_matches_port(mapping: OsvPackageMapping, port: Port) -> bool:
        if mapping.product is not None:
            product = port.product or port.service
            if product.casefold() != mapping.product.casefold():
                return False

        if mapping.service is not None and port.service.casefold() != mapping.service.casefold():
            return False

        if mapping.cpe_prefix is not None:
            prefix = mapping.cpe_prefix.casefold()
            matched = any(
                cpe.casefold().startswith(prefix)
                or (
                    (normalized := normalize_cpe23(cpe)) is not None
                    and normalized.casefold().startswith(prefix)
                )
                for cpe in port.cpe
            )
            if not matched:
                return False

        return True

    def _osv_result_to_findings(
        self,
        resolved: ResolvedOsvQuery,
        result: dict[str, Any],
        *,
        client: OsvClient,
        minimum_cvss: float,
        nvd_by_cve: dict[str, Finding],
    ) -> list[Finding]:
        vulns = result.get("vulns", [])
        if not isinstance(vulns, list):
            return []

        findings: list[Finding] = []
        for vuln in vulns:
            detailed_vuln = self._osv_detail_payload(vuln, client)
            if detailed_vuln is None:
                continue

            osv_id = detailed_vuln.get("id")
            if not isinstance(osv_id, str) or not osv_id:
                continue

            aliases = [alias for alias in aliases_from_osv(detailed_vuln) if alias != osv_id]
            cve_alias = preferred_cve_from_osv(detailed_vuln)
            osv_cvss = extract_cvss_from_osv(detailed_vuln)
            related_nvd = nvd_by_cve.get(cve_alias.upper()) if cve_alias else None

            if related_nvd is not None:
                cvss = related_nvd.cvss
                match_method = "osv-alias-enrichment"
                confidence = 0.85
                validation_required = True
            else:
                cvss = osv_cvss
                match_method = "osv-package-version"
                confidence = 0.70
                validation_required = True

            if cvss is None or cvss < minimum_cvss:
                continue

            primary_id = cve_alias or osv_id
            references = references_from_osv(detailed_vuln)
            findings.append(
                Finding(
                    finding_id=osv_id,
                    cve_id=cve_alias,
                    aliases=aliases,
                    title=f"{primary_id}: {summary_from_osv(detailed_vuln)}",
                    host=resolved.host_ip,
                    port=resolved.port,
                    source_agents=[self.agent_name],
                    intel_sources=["osv"],
                    source_type=SourceType.SERVICE,
                    match_method=match_method,
                    validation_required=validation_required,
                    severity=self._severity_for_cvss(cvss),
                    cvss=cvss,
                    confidence=confidence,
                    evidence=self._osv_evidence(resolved, osv_id, match_method),
                    references=references,
                    remediation=(
                        "Treat this as package-level intelligence for manual validation, "
                        "confirm the deployed package provenance on the authorized target, "
                        "and apply the approved remediation if affected."
                    ),
                    risk_score=round(cvss * confidence, 2),
                )
            )

        return findings

    @staticmethod
    def _osv_detail_payload(vuln: dict[str, Any], client: OsvClient) -> dict[str, Any] | None:
        vuln_id = vuln.get("id")
        if not isinstance(vuln_id, str) or not vuln_id:
            return None

        if all(key in vuln for key in ("aliases", "references")) and (
            extract_cvss_from_osv(vuln) is not None or preferred_cve_from_osv(vuln) is not None
        ):
            return vuln

        try:
            detailed = client.get_vuln(vuln_id)
        except OsvClientError as exc:
            LOGGER.debug("OSV detail lookup failed for %s: %s", vuln_id, exc)
            return vuln if isinstance(vuln, dict) else None
        if not isinstance(detailed, dict):
            return vuln if isinstance(vuln, dict) else None
        return {**vuln, **detailed}

    def _nvd_payload_to_findings(
        self,
        host_ip: str,
        port: Port,
        payload: dict[str, Any],
        *,
        query_label: str,
        confidence: float,
        minimum_cvss: float,
        allow_range_matches: bool,
    ) -> list[Finding]:
        vulnerabilities = payload.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return []

        findings: list[Finding] = []
        for item in vulnerabilities:
            cve = item.get("cve", {})
            if not isinstance(cve, dict):
                continue
            if str(cve.get("vulnStatus", "")).casefold() == "rejected":
                continue
            if not self._appears_relevant_to_service(port, cve):
                continue

            cve_id = cve.get("id")
            if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
                continue

            cvss, _ = extract_cvss(cve)
            if cvss is None or cvss < minimum_cvss:
                continue
            references = references_from_nvd(cve)
            if not references:
                continue
            match_method = self._confirmed_match_method(port, cve)
            if match_method is None:
                continue
            if match_method == "cpe-range" and not allow_range_matches:
                continue
            if query_label.startswith("keywordSearch="):
                continue

            findings.append(
                Finding(
                    finding_id=cve_id,
                    cve_id=cve_id,
                    aliases=[],
                    title=f"{cve_id}: {english_description(cve)}",
                    host=host_ip,
                    port=port.port,
                    source_agents=[self.agent_name],
                    intel_sources=["nvd"],
                    source_type=SourceType.SERVICE,
                    match_method=match_method,
                    validation_required=False,
                    severity=self._severity_for_cvss(cvss),
                    cvss=cvss,
                    confidence=0.95 if match_method == "cpe-exact" else 0.90,
                    evidence=self._nvd_evidence(host_ip, port, query_label, match_method),
                    references=references,
                    remediation=(
                        "Review vendor and NVD references, validate applicability for the "
                        "authorized target, and apply the approved remediation."
                    ),
                    risk_score=round(cvss * (0.95 if match_method == "cpe-exact" else 0.90), 2),
                )
            )
        return findings

    @staticmethod
    def _keyword_for_port(port: Port) -> str | None:
        product = port.product or port.service
        if not product or not port.version:
            return None
        return f"{product} {port.version}"

    def _confirmed_match_method(self, port: Port, cve: dict[str, Any]) -> str | None:
        normalized_cpes = [value for value in (normalize_cpe23(cpe) for cpe in port.cpe) if value]
        if not normalized_cpes:
            return None

        configurations = cve.get("configurations", [])
        if not isinstance(configurations, list):
            return None

        best: str | None = None
        for config in configurations:
            nodes = config.get("nodes", [])
            if not isinstance(nodes, list):
                continue
            for node in nodes:
                match = self._node_match(node, normalized_cpes)
                if match == "cpe-exact":
                    return match
                if match == "cpe-range":
                    best = match
        return best

    def _node_match(self, node: dict[str, Any], normalized_cpes: list[str]) -> str | None:
        operator = str(node.get("operator", "OR")).upper()
        negate = bool(node.get("negate", False))

        child_results = []
        for child in node.get("nodes", []):
            if isinstance(child, dict):
                child_results.append(self._node_match(child, normalized_cpes))
        cpe_results = []
        for match in node.get("cpeMatch", []):
            if isinstance(match, dict):
                cpe_results.append(self._cpe_match_result(match, normalized_cpes))

        results = [result for result in [*child_results, *cpe_results] if result is not None]
        if negate:
            return None
        if operator == "AND":
            if not child_results and not cpe_results:
                return None
            if any(result is None for result in [*child_results, *cpe_results]):
                return None
            return "cpe-exact" if "cpe-exact" in results else "cpe-range"
        if operator == "OR":
            if "cpe-exact" in results:
                return "cpe-exact"
            if "cpe-range" in results:
                return "cpe-range"
        return None

    def _cpe_match_result(self, cpe_match: dict[str, Any], normalized_cpes: list[str]) -> str | None:
        if cpe_match.get("vulnerable") is not True:
            return None
        criteria = cpe_match.get("criteria")
        if not isinstance(criteria, str):
            return None

        for target in normalized_cpes:
            result = self._criteria_matches_target(criteria, cpe_match, target)
            if result is not None:
                return result
        return None

    def _criteria_matches_target(
        self,
        criteria: str,
        cpe_match: dict[str, Any],
        target: str,
    ) -> str | None:
        criteria_parts = criteria.split(":")
        target_parts = target.split(":")
        if len(criteria_parts) < 6 or len(target_parts) < 6:
            return None
        if criteria_parts[:5] != target_parts[:5]:
            return None

        criteria_version = criteria_parts[5]
        target_version = target_parts[5]
        if criteria_version not in {"*", "-"}:
            return "cpe-exact" if criteria_version.casefold() == target_version.casefold() else None

        has_range = any(
            cpe_match.get(key) is not None
            for key in (
                "versionStartIncluding",
                "versionStartExcluding",
                "versionEndIncluding",
                "versionEndExcluding",
            )
        )
        if not has_range:
            return None
        return (
            "cpe-range"
            if self._version_in_range(
                target_version,
                start_including=cpe_match.get("versionStartIncluding"),
                start_excluding=cpe_match.get("versionStartExcluding"),
                end_including=cpe_match.get("versionEndIncluding"),
                end_excluding=cpe_match.get("versionEndExcluding"),
            )
            else None
        )

    @staticmethod
    def _version_in_range(
        version: str,
        *,
        start_including: str | None = None,
        start_excluding: str | None = None,
        end_including: str | None = None,
        end_excluding: str | None = None,
    ) -> bool:
        if start_including is not None and CveLookupAgent._compare_versions(version, start_including) < 0:
            return False
        if start_excluding is not None and CveLookupAgent._compare_versions(version, start_excluding) <= 0:
            return False
        if end_including is not None and CveLookupAgent._compare_versions(version, end_including) > 0:
            return False
        if end_excluding is not None and CveLookupAgent._compare_versions(version, end_excluding) >= 0:
            return False
        return True

    @staticmethod
    def _compare_versions(left: str, right: str) -> int:
        left_tokens = CveLookupAgent._version_tokens(left)
        right_tokens = CveLookupAgent._version_tokens(right)
        for l_token, r_token in zip(left_tokens, right_tokens, strict=False):
            if l_token == r_token:
                continue
            if l_token < r_token:
                return -1
            return 1
        if len(left_tokens) == len(right_tokens):
            return 0
        return -1 if len(left_tokens) < len(right_tokens) else 1

    @staticmethod
    def _version_tokens(value: str) -> list[tuple[int, int | str]]:
        tokens = re.findall(r"\d+|[A-Za-z]+", value)
        normalized: list[tuple[int, int | str]] = []
        for token in tokens:
            if token.isdigit():
                normalized.append((0, int(token)))
            else:
                normalized.append((1, token.casefold()))
        return normalized

    @staticmethod
    def _appears_relevant_to_service(port: Port, cve: dict[str, Any]) -> bool:
        service = (port.service or "").casefold()
        text = " ".join(
            [
                str(cve.get("id", "")),
                english_description(cve),
            ]
        ).casefold()
        if service == "ssh":
            client_only_markers = (
                "ssh-agent",
                "x11 forwarding",
                "forwarded unix-domain sockets",
                "local users",
                "pkcs#11",
                "client in openssh",
                "openssh client",
            )
            server_markers = ("sshd", "server", "remote attackers", "remote attacker")
            if any(marker in text for marker in client_only_markers) and not any(
                marker in text for marker in server_markers
            ):
                return False
        return True

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
        if record.origin:
            evidence += f" Fixture source: {record.origin}."
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
        if record.origin:
            evidence += f" Fixture source: {record.origin}."
        return evidence

    @staticmethod
    def _nvd_evidence(host_ip: str, port: Port, query_label: str, match_method: str) -> str:
        product = port.product or port.service
        version = port.version or "unknown"
        evidence = (
            f"NVD live/cache lookup matched {product} {version} on "
            f"{host_ip}:{port.port}/{port.protocol} via {query_label}. "
            f"Confirmed by {match_method}."
        )
        if port.cpe:
            evidence += f" Enumerated CPE: {', '.join(port.cpe)}."
        return evidence

    @staticmethod
    def _osv_evidence(
        resolved: ResolvedOsvQuery,
        osv_id: str,
        match_method: str,
    ) -> str:
        evidence = (
            f"OSV package lookup matched explicit mapping "
            f"{resolved.ecosystem}/{resolved.package} {resolved.version} for "
            f"{resolved.product} on {resolved.host_ip}:{resolved.port}/{resolved.protocol}. "
            f"Match method: {match_method}. This is package-level intelligence, not a "
            f"CPE-exact confirmation. OSV ID: {osv_id}."
        )
        if resolved.notes:
            evidence += f" Mapping note: {resolved.notes}."
        return evidence
