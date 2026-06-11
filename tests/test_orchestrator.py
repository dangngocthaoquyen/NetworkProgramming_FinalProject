import asyncio
import json
import time
from pathlib import Path

import pytest

from app.orchestrator import Phase3Orchestrator
from app.agents.cve_lookup_agent import CveLookupAgent
from app.schemas.agent_result_schema import AgentResult, AgentStatus
from app.schemas.enum_schema import EnumInput


ROOT = Path(__file__).resolve().parents[1]


def write_config(path: Path) -> None:
    path.write_text(
        "safety:\n"
        "  allowed_cidrs:\n"
        '    - "127.0.0.0/8"\n'
        '    - "192.168.0.0/16"\n'
        "  block_public_ip: true\n"
        "scanner:\n"
        "  max_concurrency: 2\n"
        "  enable_nuclei: false\n",
        encoding="utf-8",
    )


def write_enum(path: Path, ip: str = "192.168.1.10") -> None:
    path.write_text(
        json.dumps(
            {
                "scan_id": "scan-001",
                "target": "authorized-lab",
                "hosts": [{"ip": ip, "ports": []}],
            }
        ),
        encoding="utf-8",
    )


class SuccessfulAgent:
    agent_name = "successful_agent"

    async def run(self, enum_input: EnumInput) -> AgentResult:
        return AgentResult(
            agent_name=self.agent_name,
            scan_id=enum_input.scan_id,
            status=AgentStatus.SUCCESS,
            data={
                "findings": [
                    {
                        "finding_id": "CVE-2099-9999",
                        "title": "Test finding",
                        "severity": "high",
                        "cvss": 8.0,
                        "confidence": 0.9,
                        "evidence": "Authorized test evidence.",
                        "remediation": "Apply the test remediation.",
                        "risk_score": 7.2,
                    }
                ]
            },
        )


class FailingAgent:
    agent_name = "failing_agent"

    async def run(self, enum_input: EnumInput) -> AgentResult:
        raise RuntimeError("mock agent failure")


class SlowAgent:
    def __init__(self, name: str, delay_seconds: float = 0.1) -> None:
        self.agent_name = name
        self.delay_seconds = delay_seconds

    async def run(self, enum_input: EnumInput) -> AgentResult:
        await asyncio.sleep(self.delay_seconds)
        return AgentResult(
            agent_name=self.agent_name,
            scan_id=enum_input.scan_id,
            status=AgentStatus.SUCCESS,
            data={"findings": []},
        )


@pytest.mark.asyncio
async def test_pipeline_writes_artifacts_and_continues_after_agent_error(
    tmp_path: Path,
):
    config = tmp_path / "config.yaml"
    enum_path = tmp_path / "enum.json"
    output_dir = tmp_path / "reports" / "scan-001"
    logs_dir = tmp_path / "logs"
    write_config(config)
    write_enum(enum_path)

    orchestrator = Phase3Orchestrator(
        config_path=config,
        logs_dir=logs_dir,
        pi_dir=tmp_path / ".pi",
        agents=[SuccessfulAgent(), FailingAgent()],
    )
    artifacts = await orchestrator.run(enum_path, output_dir)

    assert artifacts.vulnerability_output.summary.total == 1
    assert artifacts.vuln_path.exists()
    assert artifacts.report_path.exists()
    assert artifacts.log_path == logs_dir / "scan-001.log"
    assert artifacts.pi_vuln_path.exists()
    assert artifacts.pi_report_path.exists()
    assert artifacts.pi_log_path.exists()
    assert (tmp_path / ".pi" / "outputs" / "cve_candidates.json").exists()
    assert (tmp_path / ".pi" / "outputs" / "nuclei_results.json").exists()
    assert "mock agent failure" in artifacts.log_path.read_text(encoding="utf-8")
    assert "agent_timing" in artifacts.log_path.read_text(encoding="utf-8")

    vuln_payload = json.loads(artifacts.vuln_path.read_text(encoding="utf-8"))
    assert (
        vuln_payload["findings"][0]["finding_id"]
        == "CVE-2099-9999-unknown-host-os-service"
    )
    report = artifacts.report_path.read_text(encoding="utf-8")
    assert "failing_agent" in report
    assert "## Executive Summary" in report
    assert "## Scope" in report
    assert "## OS Inventory" in report
    assert "## Findings by Severity" in report
    assert "## Technical Details" in report
    assert "## Remediation" in report
    assert "## Appendix" in report


@pytest.mark.asyncio
async def test_pipeline_blocks_out_of_scope_enum_before_agents_run(tmp_path: Path):
    config = tmp_path / "config.yaml"
    enum_path = tmp_path / "enum.json"
    write_config(config)
    write_enum(enum_path, ip="8.8.8.8")

    orchestrator = Phase3Orchestrator(
        config_path=config,
        logs_dir=tmp_path / "logs",
        pi_dir=tmp_path / ".pi",
        agents=[SuccessfulAgent()],
    )

    with pytest.raises(ValueError, match="Public IP is blocked"):
        await orchestrator.run(enum_path, tmp_path / "reports" / "scan-001")


@pytest.mark.asyncio
async def test_pipeline_can_contain_service_and_os_findings(tmp_path: Path):
    config = tmp_path / "config.yaml"
    enum_path = tmp_path / "enum.json"
    write_config(config)
    enum_path.write_text(
        json.dumps(
            {
                "scan_id": "mixed-sources",
                "target": "authorized-lab",
                "hosts": [
                    {
                        "ip": "192.168.1.10",
                        "os": {
                            "name": "Ubuntu",
                            "version": "22.04",
                            "kernel": "5.15.0",
                            "architecture": "x86_64",
                            "confidence": 92,
                            "source": "phase2-os-fingerprint",
                        },
                        "ports": [
                            {
                                "port": 8080,
                                "service": "http",
                                "product": "Apache httpd",
                                "version": "2.4.49",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    orchestrator = Phase3Orchestrator(
        config_path=config,
        logs_dir=tmp_path / "logs",
        pi_dir=tmp_path / ".pi",
        agents=[CveLookupAgent()],
    )

    artifacts = await orchestrator.run(enum_path, tmp_path / "reports" / "mixed")

    source_types = {
        finding.source_type.value for finding in artifacts.vulnerability_output.findings
    }
    assert source_types == {"service", "os"}
    report = artifacts.report_path.read_text(encoding="utf-8")
    assert "## OS Inventory" in report
    assert "Ubuntu 22.04" in report


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sample_name", "expected_source_type"),
    [
        ("enum_lab_no_os.json", "service"),
        ("enum_lab_linux_os.json", "os"),
        ("enum_lab_windows_os.json", "os"),
        ("enum_lab_full.json", "os"),
    ],
)
async def test_focused_samples_run_successfully(
    tmp_path: Path, sample_name: str, expected_source_type: str
):
    orchestrator = Phase3Orchestrator(
        logs_dir=tmp_path / "logs",
        pi_dir=tmp_path / ".pi",
    )

    artifacts = await orchestrator.run(
        ROOT / "data" / "samples" / sample_name,
        tmp_path / "outputs" / Path(sample_name).stem,
    )

    assert artifacts.vulnerability_output.findings
    assert expected_source_type in {
        finding.source_type.value for finding in artifacts.vulnerability_output.findings
    }
    report = artifacts.report_path.read_text(encoding="utf-8")
    assert "## OS Inventory" in report
    assert (
        "deduplicated by host, port, CVE ID, title, and source type" in report
    )


@pytest.mark.asyncio
async def test_full_sample_contains_service_and_os_assessment_data(tmp_path: Path):
    orchestrator = Phase3Orchestrator(
        logs_dir=tmp_path / "logs",
        pi_dir=tmp_path / ".pi",
    )

    artifacts = await orchestrator.run(
        ROOT / "data" / "samples" / "enum_lab_full.json",
        tmp_path / "outputs" / "full",
    )

    source_types = {
        finding.source_type.value for finding in artifacts.vulnerability_output.findings
    }
    assert source_types == {"service", "os", "web-template"}
    finding_ids = [
        finding.finding_id for finding in artifacts.vulnerability_output.findings
    ]
    assert len(finding_ids) == len(set(finding_ids))
    for finding in artifacts.vulnerability_output.findings:
        expected_severity = (
            "critical"
            if finding.cvss >= 9.0
            else "high"
            if finding.cvss >= 7.0
            else "medium"
            if finding.cvss >= 4.0
            else "low"
            if finding.cvss > 0
            else "info"
        )
        assert finding.severity.value == expected_severity

    summary = artifacts.vulnerability_output.summary
    assert summary.total == len(artifacts.vulnerability_output.findings)
    assert summary.critical == sum(
        finding.severity.value == "critical"
        for finding in artifacts.vulnerability_output.findings
    )
    assert summary.high == sum(
        finding.severity.value == "high"
        for finding in artifacts.vulnerability_output.findings
    )
    assert summary.medium == sum(
        finding.severity.value == "medium"
        for finding in artifacts.vulnerability_output.findings
    )
    assert summary.low == sum(
        finding.severity.value == "low"
        for finding in artifacts.vulnerability_output.findings
    )
    assert summary.info == sum(
        finding.severity.value == "info"
        for finding in artifacts.vulnerability_output.findings
    )
    report = artifacts.report_path.read_text(encoding="utf-8")
    assert "## OS Inventory" in report
    assert "## Enumeration Inventory" in report
    assert "192.168.56.21:8080/tcp" in report
    assert "Apache httpd 2.4.49" in report
    assert "linux-lab.local" in report
    assert "cpe:/a:apache:http_server:2.4.49" in report
    assert "/admin" in report
    assert "/api/v1/users" in report


@pytest.mark.asyncio
async def test_independent_agents_run_concurrently(tmp_path: Path):
    config = tmp_path / "config.yaml"
    enum_path = tmp_path / "enum.json"
    write_config(config)
    write_enum(enum_path)
    orchestrator = Phase3Orchestrator(
        config_path=config,
        logs_dir=tmp_path / "logs",
        pi_dir=tmp_path / ".pi",
        agents=[SlowAgent("slow_agent_a"), SlowAgent("slow_agent_b")],
    )

    started = time.perf_counter()
    artifacts = await orchestrator.run(enum_path, tmp_path / "reports" / "parallel")
    elapsed = time.perf_counter() - started

    assert elapsed < 0.16
    timings = [
        result.data["agent_timing"] for result in artifacts.agent_results
    ]
    first_start = min(item["started_at"] for item in timings)
    last_start = max(item["started_at"] for item in timings)
    first_end = min(item["ended_at"] for item in timings)
    assert first_start <= last_start < first_end
