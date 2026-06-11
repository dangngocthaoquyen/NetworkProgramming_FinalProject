from pathlib import Path

import pytest

from app.agents.cve_lookup_agent import CveLookupAgent
from app.schemas.agent_result_schema import AgentStatus
from app.schemas.enum_schema import EnumInput
from app.schemas.vuln_schema import SourceType


def make_enum(product: str, version: str | None) -> EnumInput:
    return EnumInput.model_validate(
        {
            "scan_id": "cve-test",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "ports": [
                        {
                            "port": 80,
                            "service": "http",
                            "product": product,
                            "version": version,
                        }
                    ],
                }
            ],
        }
    )


def test_exact_version_match_has_high_confidence():
    findings = CveLookupAgent().lookup(make_enum("Apache httpd", "2.4.49"))

    assert len(findings) == 1
    assert findings[0].finding_id == "CVE-2021-41773"
    assert findings[0].confidence == 0.95
    assert findings[0].source_type is SourceType.SERVICE


def test_version_range_match_has_expected_confidence():
    findings = CveLookupAgent().lookup(make_enum("nginx", "1.18.0"))

    assert len(findings) == 1
    assert findings[0].finding_id == "CVE-2099-0001"
    assert findings[0].confidence == 0.80


def test_product_only_match_has_low_confidence():
    findings = CveLookupAgent().lookup(make_enum("Legacy Web Server", None))

    assert len(findings) == 1
    assert findings[0].confidence == 0.40


def test_only_returns_cves_with_cvss_at_least_seven():
    findings = CveLookupAgent().lookup(make_enum("nginx", "9.0.0"))

    assert findings == []


@pytest.mark.asyncio
async def test_run_returns_common_agent_result():
    result = await CveLookupAgent().run(make_enum("OpenSSH", "7.2"))

    assert result.status is AgentStatus.SUCCESS
    assert result.data["findings"][0]["finding_id"] == "CVE-2016-0777"


@pytest.mark.asyncio
async def test_database_error_does_not_escape_agent(tmp_path: Path):
    result = await CveLookupAgent(tmp_path / "missing.json").run(
        make_enum("OpenSSH", "7.2")
    )

    assert result.status is AgentStatus.FAILED
    assert result.errors


def test_linux_os_lookup_returns_host_level_finding():
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "linux-os",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "os": {
                        "name": "Ubuntu",
                        "version": "22.04",
                        "kernel": "5.15.0",
                    },
                    "ports": [],
                }
            ],
        }
    )

    findings = CveLookupAgent().lookup(enum_input)

    assert findings[0].finding_id == "CVE-2099-1001"
    assert findings[0].source_type is SourceType.OS
    assert findings[0].port is None
    assert "kernel=5.15.0" in findings[0].evidence


def test_windows_os_lookup_returns_host_level_finding():
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "windows-os",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.11",
                    "os": {"name": "Windows 10", "build": "19045"},
                    "ports": [],
                }
            ],
        }
    )

    findings = CveLookupAgent().lookup(enum_input)

    assert findings[0].finding_id == "CVE-2099-1002"
    assert findings[0].source_type is SourceType.OS
    assert findings[0].port is None


def test_windows_name_and_version_style_matches():
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "windows-os-split-name",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.11",
                    "os": {
                        "name": "Windows",
                        "version": "10",
                        "build": "19045",
                    },
                    "ports": [],
                }
            ],
        }
    )

    findings = CveLookupAgent().lookup(enum_input)

    assert findings[0].finding_id == "CVE-2099-1002"


def test_os_finding_confidence_combines_fingerprint_confidence():
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "windows-confidence",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.11",
                    "os": {
                        "name": "Windows",
                        "version": "10",
                        "build": "19045",
                        "confidence": 88,
                    },
                    "ports": [],
                }
            ],
        }
    )

    findings = CveLookupAgent().lookup(enum_input)

    assert findings[0].confidence == 0.836


def test_os_finding_without_fingerprint_confidence_keeps_default():
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "windows-default-confidence",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.11",
                    "os": {"name": "Windows 10", "build": "19045"},
                    "ports": [],
                }
            ],
        }
    )

    findings = CveLookupAgent().lookup(enum_input)

    assert findings[0].confidence == 0.95


def test_service_and_os_cpe_are_included_in_evidence():
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "cpe-evidence",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "os": {
                        "name": "Ubuntu",
                        "version": "22.04",
                        "kernel": "5.15.0",
                        "cpe": ["cpe:/o:canonical:ubuntu_linux:22.04"],
                    },
                    "ports": [
                        {
                            "port": 8080,
                            "service": "http",
                            "product": "Apache httpd",
                            "version": "2.4.49",
                            "cpe": ["cpe:/a:apache:http_server:2.4.49"],
                        }
                    ],
                }
            ],
        }
    )

    findings = CveLookupAgent().lookup(enum_input)

    assert any("cpe:/a:apache:http_server:2.4.49" in item.evidence for item in findings)
    assert any("cpe:/o:canonical:ubuntu_linux:22.04" in item.evidence for item in findings)
