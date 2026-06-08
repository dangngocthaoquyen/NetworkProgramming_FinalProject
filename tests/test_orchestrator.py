import json
from pathlib import Path

import pytest

from app.orchestrator import Phase3Orchestrator
from app.schemas.agent_result_schema import AgentResult, AgentStatus
from app.schemas.enum_schema import EnumInput


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

    vuln_payload = json.loads(artifacts.vuln_path.read_text(encoding="utf-8"))
    assert vuln_payload["findings"][0]["finding_id"] == "CVE-2099-9999"
    report = artifacts.report_path.read_text(encoding="utf-8")
    assert "failing_agent" in report
    assert "## Executive Summary" in report
    assert "## Scope" in report
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
