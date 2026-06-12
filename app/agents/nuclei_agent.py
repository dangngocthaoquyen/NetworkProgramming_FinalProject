"""Safety-constrained Nuclei wrapper with CLI, mock, and auto modes."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from app.schemas.agent_result_schema import AgentResult, AgentStatus
from app.schemas.enum_schema import EnumInput
from app.schemas.vuln_schema import Finding, Severity, SourceType
from app.tools.scope_guard import ScopeGuard, ScopeViolationError


DEFAULT_TIMEOUT_SECONDS = 120.0
DEFAULT_BINARY = "nuclei"
DEFAULT_MODE = "mock"
DEFAULT_SEVERITIES = ("critical", "high")
DEFAULT_EXCLUDED_TAGS = ("dos", "brute-force", "intrusive")
JETTY_CONTINUUM_URL = "http://172.28.128.3:8080/continuum"
ENV_PATTERN = re.compile(r"^\$\{(?P<name>[A-Z0-9_]+)(?::-(?P<default>.*))?\}$")


class NucleiAgent:
    """Run Nuclei only for validated in-scope URLs with safe template filters."""

    agent_name = "nuclei_agent"

    def __init__(
        self,
        config_path: str | Path = "config.yaml",
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.config_path = Path(config_path)
        self.timeout_seconds = timeout_seconds

    async def run(self, enum_input: EnumInput) -> AgentResult:
        """Run safe Nuclei checks without allowing failures to crash the pipeline."""

        scan_id = enum_input.scan_id
        try:
            config = self._load_config()
            scope_guard = ScopeGuard.from_config(self.config_path)
            scope_guard.validate_enum(enum_input)
            urls = self._validated_urls(enum_input, scope_guard)

            if not urls:
                return self._skipped(scan_id, "No in-scope URLs were present in enum input.")

            mode = config["mode"]
            if mode == "mock":
                return self._mock_result(enum_input, urls, scan_id, config)

            if mode == "cli":
                return await self._cli_result(
                    enum_input,
                    urls,
                    scan_id,
                    config,
                    allow_mock_fallback=bool(config["use_mock_fallback"]),
                )

            if mode == "auto":
                return await self._cli_result(enum_input, urls, scan_id, config, allow_mock_fallback=bool(config["use_mock_fallback"]))

            return AgentResult(
                agent_name=self.agent_name,
                scan_id=scan_id,
                status=AgentStatus.FAILED,
                message="Nuclei agent failed safely.",
                errors=[f"Unsupported nuclei.mode: {mode}"],
            )
        except Exception as exc:
            return AgentResult(
                agent_name=self.agent_name,
                scan_id=scan_id,
                status=AgentStatus.FAILED,
                message="Nuclei agent failed safely.",
                errors=[str(exc)],
            )

    async def _cli_result(
        self,
        enum_input: EnumInput,
        urls: list[str],
        scan_id: str,
        config: dict[str, Any],
        *,
        allow_mock_fallback: bool,
    ) -> AgentResult:
        binary = self._resolve_binary(config["binary"])
        if binary is None:
            return self._fallback_or_fail(
                enum_input,
                urls,
                scan_id,
                config,
                reason="Nuclei executable was not found in PATH.",
                allow_mock_fallback=allow_mock_fallback,
            )

        findings, error, command, output_file = await self._run_cli(binary, urls, config)
        if error is not None:
            return self._fallback_or_fail(
                enum_input,
                urls,
                scan_id,
                config,
                reason=error,
                allow_mock_fallback=allow_mock_fallback,
            )

        return AgentResult(
            agent_name=self.agent_name,
            scan_id=scan_id,
            status=AgentStatus.SUCCESS,
            message=f"Nuclei CLI completed with {len(findings)} critical/high matches.",
            data={
                "findings": [item.model_dump(mode="json") for item in findings],
                "execution_mode": "cli",
                "used_mock_fallback": False,
                "matched_count": len(findings),
                "scanned_urls": urls,
                "command": command,
                "output_file": output_file,
            },
        )

    def _fallback_or_fail(
        self,
        enum_input: EnumInput,
        urls: list[str],
        scan_id: str,
        config: dict[str, Any],
        *,
        reason: str,
        allow_mock_fallback: bool,
    ) -> AgentResult:
        if allow_mock_fallback:
            mock_findings = self._mock_findings(enum_input, urls, config)
            if mock_findings:
                return AgentResult(
                    agent_name=self.agent_name,
                    scan_id=scan_id,
                    status=AgentStatus.SUCCESS,
                    message=f"Nuclei CLI unavailable; offline mock returned {len(mock_findings)} findings.",
                    data={
                        "findings": [item.model_dump(mode="json") for item in mock_findings],
                        "execution_mode": "mock",
                        "used_mock_fallback": True,
                        "matched_count": len(mock_findings),
                        "scanned_urls": urls,
                    },
                    errors=[reason],
                )
        return AgentResult(
            agent_name=self.agent_name,
            scan_id=scan_id,
            status=AgentStatus.FAILED,
            message="Nuclei CLI failed.",
            errors=[reason],
        )

    def _mock_result(
        self,
        enum_input: EnumInput,
        urls: list[str],
        scan_id: str,
        config: dict[str, Any],
    ) -> AgentResult:
        findings = self._mock_findings(enum_input, urls, config)
        if findings:
            return AgentResult(
                agent_name=self.agent_name,
                scan_id=scan_id,
                status=AgentStatus.SUCCESS,
                message=f"Offline Nuclei mock returned {len(findings)} findings.",
                data={
                    "findings": [item.model_dump(mode="json") for item in findings],
                    "execution_mode": "mock",
                    "used_mock_fallback": False,
                    "matched_count": len(findings),
                    "scanned_urls": urls,
                },
            )
        return self._skipped(scan_id, "Nuclei mock mode produced no matching findings.")

    def _load_config(self) -> dict[str, Any]:
        raw: dict[str, Any] = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        nuclei = raw.get("nuclei", {}) if isinstance(raw, dict) else {}
        if not isinstance(nuclei, dict):
            raise ValueError("config.yaml nuclei must be a mapping")

        severities = tuple(str(item).lower() for item in nuclei.get("severity", DEFAULT_SEVERITIES))
        if not severities:
            raise ValueError("nuclei.severity must contain at least one value")

        return {
            "mode": str(nuclei.get("mode", DEFAULT_MODE)).lower(),
            "binary": self._resolve_env_value(str(nuclei.get("binary", DEFAULT_BINARY))),
            "severity": severities,
            "templates_dir": nuclei.get("templates_dir"),
            "timeout_seconds": float(nuclei.get("timeout_seconds", self.timeout_seconds)),
            "use_mock_fallback": bool(nuclei.get("use_mock_fallback", True)),
            "mock_db": str(nuclei.get("mock_db", "data/nuclei_mock_db.json")),
        }

    @staticmethod
    def _resolve_env_value(value: str) -> str:
        match = ENV_PATTERN.match(value)
        if match is None:
            return value

        env_name = match.group("name")
        fallback = match.group("default")
        return os.getenv(env_name) or fallback or ""

    @staticmethod
    def _resolve_binary(binary: str) -> str | None:
        if os.path.sep in binary or (os.path.altsep and os.path.altsep in binary):
            return binary if Path(binary).exists() else None
        return shutil.which(binary)

    def _mock_findings(
        self, enum_input: EnumInput, urls: list[str], config: dict[str, Any]
    ) -> list[Finding]:
        mock_path = Path(config["mock_db"])
        payload = json.loads(mock_path.read_text(encoding="utf-8"))
        findings: list[Finding] = []
        for record in payload.get("records", []):
            url = record.get("url")
            if url not in urls:
                continue
            contexts = self._enum_contexts(enum_input, url)
            matched_context = self._matching_context(record, contexts)
            if matched_context is None:
                continue

            parsed_url = urlparse(url)
            severity = Severity(str(record["severity"]).lower())
            if severity.value not in config["severity"]:
                continue
            details = [
                f"url={url}",
                f"path={matched_context['path']}",
                f"vhost={matched_context['vhost'] or 'N/A'}",
            ]
            findings.append(
                Finding(
                    finding_id=str(record["template_id"]),
                    template_id=str(record["template_id"]),
                    title=str(record["title"]),
                    host=parsed_url.hostname,
                    port=parsed_url.port or (443 if parsed_url.scheme == "https" else 80),
                    source_agents=[self.agent_name],
                    source_type=SourceType.WEB_TEMPLATE,
                    severity=severity,
                    cvss=float(record["cvss"]),
                    confidence=float(record["confidence"]),
                    evidence=f"{record['evidence']} Matched context: {', '.join(details)}.",
                    references=[str(item) for item in record.get("references", [])],
                    remediation=str(record["remediation"]),
                    risk_score=0,
                )
            )
        return findings

    async def _run_cli(
        self,
        nuclei_path: str,
        urls: list[str],
        config: dict[str, Any],
    ) -> tuple[list[Finding], str | None, list[str], str]:
        temp_path: Path | None = None
        output_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                suffix=".txt",
            ) as handle:
                handle.write("\n".join(urls))
                handle.write("\n")
                temp_path = Path(handle.name)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                suffix=".jsonl",
            ) as handle:
                output_path = Path(handle.name)

            command = [
                nuclei_path,
                "-list",
                str(temp_path),
                "-severity",
                ",".join(config["severity"]),
                "-jsonl",
                "-no-interactsh",
                "-exclude-tags",
                ",".join(DEFAULT_EXCLUDED_TAGS),
                "-duc",
                "-o",
                str(output_path),
            ]
            templates_dir = config.get("templates_dir")
            if templates_dir:
                command.extend(["-templates", str(templates_dir)])
            if bool(config.get("enable_stats")):
                command.append("-stats")

            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=config["timeout_seconds"],
            )
        except TimeoutError:
            if "process" in locals() and process.returncode is None:
                process.kill()
                await process.communicate()
            return [], "Nuclei CLI timed out.", command if "command" in locals() else [], str(output_path or "")
        except OSError as exc:
            return [], f"Nuclei CLI could not start: {exc}", command if "command" in locals() else [], str(output_path or "")
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

        if output_path is None:
            return [], "Nuclei CLI did not create an output file path.", command, ""

        if process.returncode != 0:
            reason = stderr.decode("utf-8", errors="replace").strip()
            return [], f"Nuclei CLI failed: {reason or 'unknown error'}", command, str(output_path)

        output = output_path.read_text(encoding="utf-8") if output_path.exists() else ""
        findings = self._parse_jsonl(output, allowed_severities=config["severity"])
        output_file = str(output_path)
        output_path.unlink(missing_ok=True)
        return findings, None, command, output_file

    @staticmethod
    def _enum_contexts(enum_input: EnumInput, url: str) -> list[dict[str, Any]]:
        contexts: list[dict[str, Any]] = []
        for host in enum_input.hosts:
            for web in host.web:
                if str(web.url) != url:
                    continue
                paths = list(dict.fromkeys(["/", *web.interesting_paths, *web.api_endpoints]))
                for path in paths:
                    contexts.append(
                        {
                            "path": path,
                            "vhost": web.vhost,
                            "host_vhosts": host.vhosts,
                            "technologies": web.technologies,
                            "api_endpoints": web.api_endpoints,
                            "discovered_paths": web.interesting_paths,
                        }
                    )
            for port in host.ports:
                if port.url is None or str(port.url) != url:
                    continue
                paths = list(dict.fromkeys(["/", *port.discovered_paths, *port.api_endpoints]))
                for path in paths:
                    contexts.append(
                        {
                            "path": path,
                            "vhost": port.vhost,
                            "host_vhosts": host.vhosts,
                            "technologies": port.technologies,
                            "api_endpoints": port.api_endpoints,
                            "discovered_paths": port.discovered_paths,
                        }
                    )
        return contexts

    @staticmethod
    def _matching_context(
        record: dict[str, Any], contexts: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        for context in contexts:
            required_path = record.get("path")
            required_vhost = record.get("vhost")
            required_technology = record.get("technology")
            if required_path is not None and context["path"] != required_path:
                continue
            if required_vhost is not None and required_vhost not in {
                context["vhost"],
                *context["host_vhosts"],
            }:
                continue
            if (
                required_technology is not None
                and required_technology not in context["technologies"]
            ):
                continue
            return context
        return None

    @staticmethod
    def _validated_urls(enum_input: EnumInput, scope_guard: ScopeGuard) -> list[str]:
        urls: list[str] = []
        for host in enum_input.hosts:
            for web in host.web:
                NucleiAgent._append_validated_url(urls, str(web.url), scope_guard)

            for port in host.ports:
                if port.url is None:
                    continue
                NucleiAgent._append_validated_url(urls, str(port.url), scope_guard)

        if JETTY_CONTINUUM_URL in urls:
            urls = [JETTY_CONTINUUM_URL, *[url for url in urls if url != JETTY_CONTINUUM_URL]]
        return urls

    @staticmethod
    def _append_validated_url(urls: list[str], url: str, scope_guard: ScopeGuard) -> None:
        hostname = urlparse(url).hostname
        if hostname is None:
            raise ScopeViolationError(f"URL has no hostname: {url}")

        try:
            scope_guard.validate_ip(hostname)
        except ipaddress.AddressValueError:
            scope_guard.validate_hostname(hostname)

        if url not in urls:
            urls.append(url)

    @staticmethod
    def _parse_jsonl(
        output: str,
        *,
        allowed_severities: tuple[str, ...] = DEFAULT_SEVERITIES,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            try:
                item = json.loads(line)
                info = item["info"]
                severity = Severity(str(info["severity"]).lower())
                if severity.value not in allowed_severities:
                    continue

                template_id = str(item.get("template-id") or item.get("template") or "nuclei")
                matched_at = str(
                    item.get("matched-at")
                    or item.get("host")
                    or item.get("url")
                    or "unknown"
                )
                parsed_match = urlparse(matched_at)
                references = NucleiAgent._extract_references(info)
                evidence_parts = [f"matched-at={matched_at}"]
                matched_host = item.get("host")
                if matched_host:
                    evidence_parts.append(f"host={matched_host}")
                request_url = item.get("url")
                if request_url:
                    evidence_parts.append(f"url={request_url}")
                matcher_name = item.get("matcher-name")
                if matcher_name:
                    evidence_parts.append(f"matcher={matcher_name}")
                extracted = item.get("extracted-results")
                if isinstance(extracted, list) and extracted:
                    evidence_parts.append(
                        "extracted=" + ", ".join(str(value) for value in extracted[:5])
                    )
                findings.append(
                    Finding(
                        finding_id=template_id,
                        template_id=template_id,
                        title=str(info.get("name") or template_id),
                        host=parsed_match.hostname,
                        port=parsed_match.port or (443 if parsed_match.scheme == "https" else 80 if parsed_match.hostname else None),
                        source_agents=["nuclei_agent"],
                        source_type=SourceType.WEB_TEMPLATE,
                        severity=severity,
                        cvss={
                            Severity.CRITICAL: 9.0,
                            Severity.HIGH: 7.0,
                        }[severity],
                        confidence=0.80,
                        evidence="Nuclei CLI match: " + "; ".join(evidence_parts) + ".",
                        references=references,
                        remediation=str(
                            info.get("remediation")
                            or "Review the finding and apply vendor guidance."
                        ),
                        risk_score={
                            Severity.CRITICAL: 9.0,
                            Severity.HIGH: 8.0,
                        }[severity],
                    )
                )
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue
        return findings

    @staticmethod
    def _extract_references(info: dict[str, Any]) -> list[str]:
        for key in ("reference", "references"):
            value = info.get(key)
            if isinstance(value, list):
                return [str(item) for item in value if str(item)]
            if isinstance(value, str) and value:
                return [value]
        classification = info.get("classification", {})
        if isinstance(classification, dict):
            references = classification.get("reference")
            if isinstance(references, list):
                return [str(item) for item in references if str(item)]
        return []

    def _skipped(self, scan_id: str, reason: str) -> AgentResult:
        return AgentResult(
            agent_name=self.agent_name,
            scan_id=scan_id,
            status=AgentStatus.SKIPPED,
            message=reason,
        )
