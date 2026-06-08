import asyncio
import json
from pathlib import Path

import pytest

from app.agents.nuclei_agent import NucleiAgent
from app.schemas.agent_result_schema import AgentStatus
from app.schemas.enum_schema import EnumInput


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
