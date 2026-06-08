"""Safety-constrained optional wrapper for the Nuclei scanner."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from app.schemas.agent_result_schema import AgentResult, AgentStatus
from app.schemas.enum_schema import EnumInput
from app.schemas.vuln_schema import Finding, Severity
from app.tools.scope_guard import ScopeGuard, ScopeViolationError


ALLOWED_SEVERITIES = ("critical", "high", "medium")
EXCLUDED_TAGS = ("dos", "brute-force", "intrusive")


class NucleiAgent:
    """Run Nuclei only for validated in-scope URLs with safe template filters."""

    agent_name = "nuclei_agent"

    def __init__(
        self,
        config_path: str | Path = "config.yaml",
        timeout_seconds: float = 120.0,
    ) -> None:
        self.config_path = Path(config_path)
        self.timeout_seconds = timeout_seconds

    async def run(self, enum_input: EnumInput) -> AgentResult:
        """Run safe Nuclei checks without allowing failures to crash the pipeline."""

        scan_id = enum_input.scan_id
        try:
            if not self._is_enabled():
                return self._skipped(scan_id, "Nuclei is disabled in config.yaml.")

            nuclei_path = shutil.which("nuclei")
            if nuclei_path is None:
                return self._skipped(scan_id, "Nuclei executable was not found in PATH.")

            scope_guard = ScopeGuard.from_config(self.config_path)
            scope_guard.validate_enum(enum_input)
            urls = self._validated_urls(enum_input, scope_guard)
            if not urls:
                return self._skipped(scan_id, "No in-scope URLs were present in enum input.")

            findings: list[Finding] = []
            errors: list[str] = []
            for url in urls:
                url_findings, error = await self._run_url(nuclei_path, url)
                findings.extend(url_findings)
                if error:
                    errors.append(error)

            status = AgentStatus.PARTIAL if errors and findings else (
                AgentStatus.FAILED if errors else AgentStatus.SUCCESS
            )
            return AgentResult(
                agent_name=self.agent_name,
                scan_id=scan_id,
                status=status,
                message=f"Nuclei returned {len(findings)} safe-template findings.",
                data={"findings": [item.model_dump(mode="json") for item in findings]},
                errors=errors,
            )
        except Exception as exc:
            return AgentResult(
                agent_name=self.agent_name,
                scan_id=scan_id,
                status=AgentStatus.FAILED,
                message="Nuclei agent failed safely.",
                errors=[str(exc)],
            )

    def _is_enabled(self) -> bool:
        config: dict[str, Any] = yaml.safe_load(
            self.config_path.read_text(encoding="utf-8")
        )
        scanner = config.get("scanner", {})
        return scanner.get("enable_nuclei") is True

    @staticmethod
    def _validated_urls(enum_input: EnumInput, scope_guard: ScopeGuard) -> list[str]:
        urls: list[str] = []
        for host in enum_input.hosts:
            for port in host.ports:
                if port.url is None:
                    continue

                url = str(port.url)
                hostname = urlparse(url).hostname
                if hostname is None:
                    raise ScopeViolationError(f"URL has no hostname: {url}")

                try:
                    scope_guard.validate_ip(hostname)
                except ipaddress.AddressValueError:
                    scope_guard.validate_hostname(hostname)

                if url not in urls:
                    urls.append(url)
        return urls

    async def _run_url(
        self, nuclei_path: str, url: str
    ) -> tuple[list[Finding], str | None]:
        command = [
            nuclei_path,
            "-u",
            url,
            "-jsonl",
            "-silent",
            "-no-interactsh",
            "-severity",
            ",".join(ALLOWED_SEVERITIES),
            "-exclude-tags",
            ",".join(EXCLUDED_TAGS),
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout_seconds
            )
        except TimeoutError:
            if "process" in locals() and process.returncode is None:
                process.kill()
                await process.communicate()
            return [], f"Nuclei timed out for URL: {url}"
        except OSError as exc:
            return [], f"Nuclei could not start for {url}: {exc}"

        if process.returncode != 0:
            reason = stderr.decode("utf-8", errors="replace").strip()
            return [], f"Nuclei failed for {url}: {reason or 'unknown error'}"

        return self._parse_jsonl(stdout.decode("utf-8", errors="replace")), None

    @staticmethod
    def _parse_jsonl(output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            try:
                item = json.loads(line)
                info = item["info"]
                severity = Severity(str(info["severity"]).lower())
                if severity.value not in ALLOWED_SEVERITIES:
                    continue

                template_id = str(item.get("template-id") or item.get("template") or "nuclei")
                matched_at = str(item.get("matched-at") or item.get("host") or "unknown")
                parsed_match = urlparse(matched_at)
                findings.append(
                    Finding(
                        finding_id=template_id,
                        title=str(info.get("name") or template_id),
                        host=parsed_match.hostname,
                        port=parsed_match.port,
                        source_agents=["nuclei_agent"],
                        severity=severity,
                        cvss=None,
                        confidence=0.80,
                        evidence=f"Nuclei safe-template match at {matched_at}.",
                        remediation=str(
                            info.get("remediation")
                            or "Review the finding and apply vendor guidance."
                        ),
                        risk_score={
                            Severity.CRITICAL: 9.0,
                            Severity.HIGH: 8.0,
                            Severity.MEDIUM: 5.0,
                        }[severity],
                    )
                )
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue
        return findings

    def _skipped(self, scan_id: str, reason: str) -> AgentResult:
        return AgentResult(
            agent_name=self.agent_name,
            scan_id=scan_id,
            status=AgentStatus.SKIPPED,
            message=reason,
        )
