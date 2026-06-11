import asyncio
import json
from pathlib import Path

import pytest

from app.agents.nuclei_agent import NucleiAgent
from app.schemas.agent_result_schema import AgentStatus
from app.schemas.enum_schema import EnumInput
from app.schemas.vuln_schema import SourceType


def make_enum(url: str = "http://192.168.1.10/") -> EnumInput:
    return EnumInput.model_validate(
        {
            "scan_id": "nuclei-test",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "ports": [{"port": 80, "service": "http", "url": url}],
                }
            ],
        }
    )


def write_config(path: Path, enabled: bool) -> None:
    path.write_text(
        "safety:\n"
        "  allowed_cidrs:\n"
        '    - "127.0.0.0/8"\n'
        '    - "192.168.0.0/16"\n'
        "  block_public_ip: true\n"
        "scanner:\n"
        f"  enable_nuclei: {str(enabled).lower()}\n",
        encoding="utf-8",
    )


def write_mock_config(path: Path, mock_db: Path) -> None:
    path.write_text(
        "safety:\n"
        "  allowed_cidrs:\n"
        '    - "192.168.0.0/16"\n'
        "  block_public_ip: true\n"
        "scanner:\n"
        "  enable_nuclei: false\n"
        "  enable_nuclei_mock: true\n"
        f'  nuclei_mock_db: "{mock_db.as_posix()}"\n',
        encoding="utf-8",
    )


@pytest.mark.asyncio
async def test_disabled_nuclei_is_skipped(monkeypatch: pytest.MonkeyPatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("subprocess must not run when Nuclei is disabled")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fail_if_called)

    result = await NucleiAgent().run(make_enum())

    assert result.status is AgentStatus.SKIPPED
    assert "disabled" in result.message.lower()


@pytest.mark.asyncio
async def test_missing_nuclei_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config = tmp_path / "config.yaml"
    write_config(config, enabled=True)
    monkeypatch.setattr("app.agents.nuclei_agent.shutil.which", lambda name: None)

    result = await NucleiAgent(config).run(make_enum())

    assert result.status is AgentStatus.SKIPPED
    assert "PATH" in result.message


@pytest.mark.asyncio
async def test_safe_command_and_jsonl_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config = tmp_path / "config.yaml"
    write_config(config, enabled=True)
    calls: list[tuple[str, ...]] = []

    class Process:
        returncode = 0

        async def communicate(self):
            line = {
                "template-id": "safe-template",
                "matched-at": "http://192.168.1.10/",
                "info": {"name": "Safe finding", "severity": "high"},
            }
            return (json.dumps(line).encode(), b"")

    async def create_process(*args, **kwargs):
        calls.append(args)
        return Process()

    monkeypatch.setattr("app.agents.nuclei_agent.shutil.which", lambda name: "nuclei")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)

    result = await NucleiAgent(config).run(make_enum())

    assert result.status is AgentStatus.SUCCESS
    assert result.data["findings"][0]["severity"] == "high"
    assert result.data["findings"][0]["source_type"] == SourceType.WEB_TEMPLATE.value
    assert "critical,high,medium" in calls[0]
    assert "dos,brute-force,intrusive" in calls[0]


@pytest.mark.asyncio
async def test_public_url_is_blocked_before_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config = tmp_path / "config.yaml"
    write_config(config, enabled=True)
    monkeypatch.setattr("app.agents.nuclei_agent.shutil.which", lambda name: "nuclei")

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("subprocess must not run for a public URL")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fail_if_called)

    result = await NucleiAgent(config).run(make_enum("http://8.8.8.8/"))

    assert result.status is AgentStatus.FAILED
    assert "Public IP is blocked" in result.errors[0]


@pytest.mark.asyncio
async def test_timeout_does_not_escape_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config = tmp_path / "config.yaml"
    write_config(config, enabled=True)

    class Process:
        returncode = None
        killed = False

        async def communicate(self):
            if not self.killed:
                await asyncio.sleep(1)
            return b"", b""

        def kill(self):
            self.killed = True
            self.returncode = -1

    async def create_process(*args, **kwargs):
        return Process()

    monkeypatch.setattr("app.agents.nuclei_agent.shutil.which", lambda name: "nuclei")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)

    result = await NucleiAgent(config, timeout_seconds=0.001).run(make_enum())

    assert result.status is AgentStatus.FAILED
    assert "timed out" in result.errors[0]


@pytest.mark.asyncio
async def test_offline_mock_returns_safe_web_template_finding(tmp_path: Path):
    mock_db = tmp_path / "mock.json"
    mock_db.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "template_id": "safe-mock",
                        "url": "http://192.168.1.10/",
                        "title": "Safe mock finding",
                        "severity": "medium",
                        "cvss": 5.3,
                        "confidence": 0.9,
                        "evidence": "Offline fixture evidence.",
                        "remediation": "Review configuration.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    config = tmp_path / "config.yaml"
    write_mock_config(config, mock_db)

    result = await NucleiAgent(config).run(make_enum())

    assert result.status is AgentStatus.SUCCESS
    assert result.data["findings"][0]["source_type"] == "web-template"
    assert result.data["findings"][0]["cvss"] == 5.3


@pytest.mark.asyncio
async def test_offline_mock_uses_enriched_path_vhost_and_technology(tmp_path: Path):
    mock_db = tmp_path / "mock.json"
    mock_db.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "template_id": "enriched-safe-mock",
                        "url": "http://192.168.1.10/",
                        "path": "/admin",
                        "vhost": "app.lab.local",
                        "technology": "Laravel",
                        "title": "Safe enriched mock finding",
                        "severity": "medium",
                        "cvss": 5.3,
                        "confidence": 0.9,
                        "evidence": "Offline fixture evidence.",
                        "remediation": "Review configuration.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    config = tmp_path / "config.yaml"
    write_mock_config(config, mock_db)
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "enriched-nuclei",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "vhosts": ["app.lab.local"],
                    "ports": [
                        {
                            "port": 80,
                            "service": "http",
                            "url": "http://192.168.1.10/",
                            "vhost": "app.lab.local",
                            "technologies": ["Laravel"],
                            "discovered_paths": ["/admin"],
                        }
                    ],
                }
            ],
        }
    )

    result = await NucleiAgent(config).run(enum_input)

    evidence = result.data["findings"][0]["evidence"]
    assert "path=/admin" in evidence
    assert "vhost=app.lab.local" in evidence
