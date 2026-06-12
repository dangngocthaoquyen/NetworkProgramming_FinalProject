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


def write_nuclei_config(
    path: Path,
    *,
    mode: str,
    mock_db: Path | None = None,
    binary: str = "nuclei",
    templates_dir: str | None = None,
    use_mock_fallback: bool = True,
) -> None:
    mock_db_value = mock_db.as_posix() if mock_db is not None else "data/nuclei_mock_db.json"
    templates_value = "null" if templates_dir is None else f'"{templates_dir}"'
    path.write_text(
        "safety:\n"
        "  allowed_cidrs:\n"
        '    - "127.0.0.0/8"\n'
        '    - "192.168.0.0/16"\n'
        "  block_public_ip: true\n"
        "scanner:\n"
        "  max_concurrency: 5\n"
        "nuclei:\n"
        f'  mode: "{mode}"\n'
        f'  binary: "{binary}"\n'
        "  severity:\n"
        '    - "critical"\n'
        '    - "high"\n'
        f"  templates_dir: {templates_value}\n"
        "  timeout_seconds: 5.0\n"
        f"  use_mock_fallback: {str(use_mock_fallback).lower()}\n"
        f'  mock_db: "{mock_db_value}"\n'
        "cve_lookup:\n"
        '  source: "mock"\n'
        "  min_cvss: 7.0\n"
        "  nvd:\n"
        '    cache_dir: "data/cache/nvd"\n'
        "    use_cache: true\n"
        "    timeout_seconds: 20.0\n",
        encoding="utf-8",
    )


def write_mock_db(path: Path, records: list[dict]) -> None:
    path.write_text(json.dumps({"records": records}), encoding="utf-8")


@pytest.mark.asyncio
async def test_mock_mode_returns_safe_web_template_finding(tmp_path: Path):
    mock_db = tmp_path / "mock.json"
    write_mock_db(
        mock_db,
        [
            {
                "template_id": "safe-mock",
                "url": "http://192.168.1.10/",
                "title": "Safe mock finding",
                "severity": "high",
                "cvss": 7.0,
                "confidence": 0.8,
                "evidence": "Offline fixture evidence.",
                "references": ["https://example.test/mock"],
                "remediation": "Review configuration.",
            }
        ],
    )
    config = tmp_path / "config.yaml"
    write_nuclei_config(config, mode="mock", mock_db=mock_db)

    result = await NucleiAgent(config).run(make_enum())

    assert result.status is AgentStatus.SUCCESS
    finding = result.data["findings"][0]
    assert finding["source_type"] == "web-template"
    assert finding["severity"] == "high"
    assert finding["template_id"] == "safe-mock"
    assert finding["references"] == ["https://example.test/mock"]


@pytest.mark.asyncio
async def test_auto_mode_falls_back_to_mock_when_binary_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mock_db = tmp_path / "mock.json"
    write_mock_db(
        mock_db,
        [
            {
                "template_id": "fallback-mock",
                "url": "http://192.168.1.10/",
                "title": "Fallback mock finding",
                "severity": "high",
                "cvss": 7.1,
                "confidence": 0.8,
                "evidence": "Offline fallback evidence.",
                "remediation": "Review configuration.",
            }
        ],
    )
    config = tmp_path / "config.yaml"
    write_nuclei_config(config, mode="auto", mock_db=mock_db)
    monkeypatch.setattr("app.agents.nuclei_agent.shutil.which", lambda _: None)

    result = await NucleiAgent(config).run(make_enum())

    assert result.status is AgentStatus.SUCCESS
    assert "offline mock returned 1 findings" in result.message.lower()
    assert "not found in PATH" in result.errors[0]


@pytest.mark.asyncio
async def test_cli_mode_missing_binary_fails_clearly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config = tmp_path / "config.yaml"
    write_nuclei_config(config, mode="cli", use_mock_fallback=False)
    monkeypatch.setattr("app.agents.nuclei_agent.shutil.which", lambda _: None)

    result = await NucleiAgent(config).run(make_enum())

    assert result.status is AgentStatus.FAILED
    assert "not found in PATH" in result.errors[0]


@pytest.mark.asyncio
async def test_cli_mode_parses_jsonl_output_and_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config = tmp_path / "config.yaml"
    write_nuclei_config(config, mode="cli", binary="nuclei")
    calls: list[tuple[str, ...]] = []

    class Process:
        returncode = 0

        async def communicate(self):
            lines = [
                {
                    "template-id": "cli-template",
                    "matched-at": "http://192.168.1.10/",
                    "info": {
                        "name": "CLI finding",
                        "severity": "high",
                        "reference": ["https://example.test/cli"],
                    },
                }
            ]
            return ("\n".join(json.dumps(item) for item in lines).encode(), b"")

    async def create_process(*args, **kwargs):
        calls.append(args)
        return Process()

    monkeypatch.setattr("app.agents.nuclei_agent.shutil.which", lambda _: "nuclei")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)

    result = await NucleiAgent(config).run(make_enum())

    assert result.status is AgentStatus.SUCCESS
    finding = result.data["findings"][0]
    assert finding["source_type"] == SourceType.WEB_TEMPLATE.value
    assert finding["template_id"] == "cli-template"
    assert finding["references"] == ["https://example.test/cli"]
    assert "-list" in calls[0]
    assert "-jsonl" in calls[0]
    assert "-no-interactsh" in calls[0]
    assert "critical,high" in calls[0]


@pytest.mark.asyncio
async def test_public_url_is_blocked_before_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config = tmp_path / "config.yaml"
    write_nuclei_config(config, mode="cli")
    monkeypatch.setattr("app.agents.nuclei_agent.shutil.which", lambda _: "nuclei")

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("subprocess must not run for a public URL")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fail_if_called)

    result = await NucleiAgent(config).run(make_enum("http://8.8.8.8/"))

    assert result.status is AgentStatus.FAILED
    assert "Public IP is blocked" in result.errors[0]


@pytest.mark.asyncio
async def test_cli_timeout_does_not_escape_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config = tmp_path / "config.yaml"
    write_nuclei_config(config, mode="cli")
    config.write_text(
        config.read_text(encoding="utf-8").replace("timeout_seconds: 5.0", "timeout_seconds: 0.001"),
        encoding="utf-8",
    )

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

    monkeypatch.setattr("app.agents.nuclei_agent.shutil.which", lambda _: "nuclei")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)

    result = await NucleiAgent(config).run(make_enum())

    assert result.status is AgentStatus.FAILED
    assert "timed out" in result.errors[0].lower()


@pytest.mark.asyncio
async def test_mock_mode_uses_enriched_path_vhost_and_technology(tmp_path: Path):
    mock_db = tmp_path / "mock.json"
    write_mock_db(
        mock_db,
        [
            {
                "template_id": "enriched-safe-mock",
                "url": "http://192.168.1.10/",
                "path": "/admin",
                "vhost": "app.lab.local",
                "technology": "Laravel",
                "title": "Safe enriched mock finding",
                "severity": "high",
                "cvss": 7.0,
                "confidence": 0.8,
                "evidence": "Offline fixture evidence.",
                "remediation": "Review configuration.",
            }
        ],
    )
    config = tmp_path / "config.yaml"
    write_nuclei_config(config, mode="mock", mock_db=mock_db)
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


@pytest.mark.asyncio
async def test_mock_mode_can_use_host_web_inventory(tmp_path: Path):
    mock_db = tmp_path / "mock.json"
    write_mock_db(
        mock_db,
        [
            {
                "template_id": "host-web-mock",
                "url": "http://192.168.1.10:631/",
                "path": "/",
                "technology": "CUPS",
                "title": "Host web inventory finding",
                "severity": "high",
                "cvss": 7.0,
                "confidence": 0.8,
                "evidence": "Offline fixture evidence.",
                "remediation": "Review configuration.",
            }
        ],
    )
    config = tmp_path / "config.yaml"
    write_nuclei_config(config, mode="mock", mock_db=mock_db)
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "host-web-nuclei",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "ports": [],
                    "web": [
                        {
                            "url": "http://192.168.1.10:631/",
                            "port": 631,
                            "service": "ipp",
                            "product": "CUPS",
                            "technologies": ["CUPS"],
                            "interesting_paths": ["/"],
                        }
                    ],
                }
            ],
        }
    )

    result = await NucleiAgent(config).run(enum_input)

    assert result.status is AgentStatus.SUCCESS
    assert result.data["findings"][0]["host"] == "192.168.1.10"


@pytest.mark.asyncio
async def test_default_mock_db_matches_metasploitable_web_inventory():
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "metasploitable-web",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "172.28.128.3",
                    "ports": [
                        {
                            "port": 80,
                            "service": "http",
                            "url": "http://172.28.128.3/",
                            "technologies": ["Apache httpd"],
                            "discovered_paths": [
                                "/chat/",
                                "/drupal/",
                                "/payroll_app.php",
                                "/phpmyadmin/",
                            ],
                        },
                        {
                            "port": 631,
                            "service": "ipp",
                            "url": "http://172.28.128.3:631/",
                            "technologies": ["CUPS"],
                        },
                    ],
                    "web": [
                        {
                            "url": "http://172.28.128.3/",
                            "port": 80,
                            "service": "http",
                            "product": "Apache httpd",
                            "technologies": ["Apache httpd"],
                            "interesting_paths": [
                                "/chat/",
                                "/drupal/",
                                "/payroll_app.php",
                                "/phpmyadmin/",
                            ],
                        },
                        {
                            "url": "http://172.28.128.3:631/",
                            "port": 631,
                            "service": "ipp",
                            "product": "CUPS",
                            "technologies": ["CUPS"],
                            "interesting_paths": ["/"],
                        },
                    ],
                }
            ],
        }
    )

    result = await NucleiAgent().run(enum_input)

    assert result.status is AgentStatus.SUCCESS
    titles = {item["title"] for item in result.data["findings"]}
    assert "Directory listing exposes web application paths" in titles
    assert "phpMyAdmin administrative path is exposed" in titles
    assert "CUPS web interface allows risky PUT method" in titles
