"""Main orchestration flow for the Phase 3 vulnerability scanning pipeline."""

from __future__ import annotations

import asyncio
import inspect
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import yaml

from app.agents.cve_lookup_agent import CveLookupAgent
from app.agents.nuclei_agent import NucleiAgent
from app.merge.deduplicate import deduplicate_findings
from app.merge.scoring import score_finding
from app.reports.markdown_report import render_markdown_report
from app.schemas.agent_result_schema import AgentResult, AgentStatus
from app.schemas.enum_schema import EnumInput
from app.schemas.vuln_schema import Finding, Severity, VulnerabilityOutput, VulnerabilitySummary
from app.tools.scope_guard import ScopeGuard


class Agent(Protocol):
    """Common runtime interface supported by Phase 3 agents."""

    agent_name: str

    def run(self, enum_input: EnumInput) -> AgentResult | Any:
        """Run the agent and return an AgentResult or awaitable AgentResult."""


@dataclass(frozen=True)
class PipelineArtifacts:
    """Paths and structured results produced by a pipeline run."""

    vulnerability_output: VulnerabilityOutput
    agent_results: tuple[AgentResult, ...]
    vuln_path: Path
    report_path: Path
    log_path: Path
    pi_vuln_path: Path
    pi_report_path: Path
    pi_log_path: Path


class Phase3Orchestrator:
    """Validate scope, run agents concurrently, and write Phase 3 artifacts."""

    def __init__(
        self,
        config_path: str | Path = "config.yaml",
        logs_dir: str | Path = "logs",
        pi_dir: str | Path = ".pi",
        agents: list[Agent] | None = None,
    ) -> None:
        self.config_path = Path(config_path)
        self.logs_dir = Path(logs_dir)
        self.pi_dir = Path(pi_dir)
        self.config = self._load_config()
        self.max_concurrency = self._max_concurrency()
        self.scope_guard = ScopeGuard.from_config(self.config_path)
        self.agents: list[Agent] = agents or [
            CveLookupAgent(),
            NucleiAgent(config_path=self.config_path),
        ]

    async def run(
        self, enum_path: str | Path, output_dir: str | Path
    ) -> PipelineArtifacts:
        """Run the complete authorized Phase 3 pipeline."""

        enum_input = self._load_enum(enum_path)
        self.scope_guard.validate_enum(enum_input)

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.logs_dir / f"{output_path.name}.log"

        semaphore = asyncio.Semaphore(self.max_concurrency)
        raw_results = await asyncio.gather(
            *(self._run_agent(agent, enum_input, semaphore) for agent in self.agents),
            return_exceptions=True,
        )
        agent_results = tuple(
            self._normalize_result(agent, result, enum_input.scan_id)
            for agent, result in zip(self.agents, raw_results, strict=True)
        )

        vulnerability_output = self._merge_results(enum_input.scan_id, agent_results)
        vuln_path = output_path / "vuln.json"
        report_path = output_path / "report.md"
        vuln_path.write_text(
            vulnerability_output.model_dump_json(indent=2),
            encoding="utf-8",
        )
        report_path.write_text(
            render_markdown_report(vulnerability_output, enum_input, agent_results),
            encoding="utf-8",
        )
        log_path.write_text(self._render_log(agent_results), encoding="utf-8")
        pi_vuln_path, pi_report_path, pi_log_path = self._write_pi_artifacts(
            vulnerability_output,
            report_path.read_text(encoding="utf-8"),
            log_path.read_text(encoding="utf-8"),
            agent_results,
        )

        return PipelineArtifacts(
            vulnerability_output=vulnerability_output,
            agent_results=agent_results,
            vuln_path=vuln_path,
            report_path=report_path,
            log_path=log_path,
            pi_vuln_path=pi_vuln_path,
            pi_report_path=pi_report_path,
            pi_log_path=pi_log_path,
        )

    async def _run_agent(
        self, agent: Agent, enum_input: EnumInput, semaphore: asyncio.Semaphore
    ) -> AgentResult:
        async with semaphore:
            if inspect.iscoroutinefunction(agent.run):
                result = await agent.run(enum_input)
            else:
                result = await asyncio.to_thread(agent.run, enum_input)
            if not isinstance(result, AgentResult):
                raise TypeError(f"{agent.agent_name} returned an invalid result")
            return result

    @staticmethod
    def _normalize_result(
        agent: Agent, result: AgentResult | BaseException, scan_id: str
    ) -> AgentResult:
        if isinstance(result, AgentResult):
            return result
        return AgentResult(
            agent_name=agent.agent_name,
            scan_id=scan_id,
            status=AgentStatus.FAILED,
            message="Agent raised an unhandled exception.",
            errors=[str(result)],
        )

    @staticmethod
    def _merge_results(
        scan_id: str, agent_results: tuple[AgentResult, ...]
    ) -> VulnerabilityOutput:
        raw_findings: list[Finding] = []
        for result in agent_results:
            for raw_finding in result.data.get("findings", []):
                finding = Finding.model_validate(raw_finding)
                if not finding.source_agents:
                    finding = finding.model_copy(
                        update={"source_agents": [result.agent_name]}
                    )
                raw_findings.append(finding)

        findings = sorted(
            (score_finding(finding) for finding in deduplicate_findings(raw_findings)),
            key=lambda item: (-item.risk_score, item.finding_id),
        )
        counts = {severity: 0 for severity in Severity}
        for finding in findings:
            counts[finding.severity] += 1

        return VulnerabilityOutput(
            scan_id=scan_id,
            summary=VulnerabilitySummary(
                total=len(findings),
                critical=counts[Severity.CRITICAL],
                high=counts[Severity.HIGH],
                medium=counts[Severity.MEDIUM],
                low=counts[Severity.LOW],
                info=counts[Severity.INFO],
            ),
            findings=findings,
        )

    @staticmethod
    def _render_log(agent_results: tuple[AgentResult, ...]) -> str:
        return "".join(
            json.dumps(result.model_dump(mode="json"), sort_keys=True) + "\n"
            for result in agent_results
        )

    def _write_pi_artifacts(
        self,
        vulnerability_output: VulnerabilityOutput,
        report: str,
        pipeline_log: str,
        agent_results: tuple[AgentResult, ...],
    ) -> tuple[Path, Path, Path]:
        outputs_dir = self.pi_dir / "outputs"
        pi_logs_dir = self.pi_dir / "logs"
        outputs_dir.mkdir(parents=True, exist_ok=True)
        pi_logs_dir.mkdir(parents=True, exist_ok=True)

        pi_vuln_path = outputs_dir / "vuln.json"
        pi_report_path = outputs_dir / "ket_qua.md"
        pi_log_path = pi_logs_dir / "pipeline.log"
        pi_vuln_path.write_text(
            vulnerability_output.model_dump_json(indent=2),
            encoding="utf-8",
        )
        pi_report_path.write_text(report, encoding="utf-8")
        pi_log_path.write_text(pipeline_log, encoding="utf-8")

        result_by_agent = {result.agent_name: result for result in agent_results}
        self._write_agent_output(
            outputs_dir / "cve_candidates.json",
            result_by_agent.get("cve_lookup_agent"),
        )
        self._write_agent_output(
            outputs_dir / "nuclei_results.json",
            result_by_agent.get("nuclei_agent"),
        )
        return pi_vuln_path, pi_report_path, pi_log_path

    @staticmethod
    def _write_agent_output(path: Path, result: AgentResult | None) -> None:
        payload = (
            result.model_dump(mode="json")
            if result is not None
            else {
                "agent_name": path.stem,
                "status": "not_run",
                "message": "This agent was not included in the pipeline run.",
                "data": {},
                "errors": [],
            }
        )
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _load_config(self) -> dict[str, Any]:
        config = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ValueError("config.yaml must contain a mapping")
        return config

    def _max_concurrency(self) -> int:
        value = self.config.get("scanner", {}).get("max_concurrency")
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError("scanner.max_concurrency must be a positive integer")
        return value

    @staticmethod
    def _load_enum(enum_path: str | Path) -> EnumInput:
        payload = json.loads(Path(enum_path).read_text(encoding="utf-8"))
        return EnumInput.model_validate(payload)


async def run_phase3(
    enum_path: str | Path,
    output_dir: str | Path,
    config_path: str | Path = "config.yaml",
) -> PipelineArtifacts:
    """Convenience entry point for the default Phase 3 pipeline."""

    return await Phase3Orchestrator(config_path=config_path).run(enum_path, output_dir)
