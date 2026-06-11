import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.agent_result_schema import AgentResult, AgentStatus
from app.schemas.enum_schema import EnumInput
from app.schemas.vuln_schema import Severity, SourceType, VulnerabilityOutput


ROOT = Path(__file__).resolve().parents[1]


def test_enum_lab_sample_is_valid():
    payload = json.loads(
        (ROOT / "data" / "samples" / "enum_lab.json").read_text(encoding="utf-8")
    )

    enum_input = EnumInput.model_validate(payload)

    assert enum_input.scan_id == "COURSE-LAB-001"
    assert str(enum_input.hosts[0].ip) == "192.168.56.10"
    assert enum_input.hosts[0].ports[1].service == "http"


@pytest.mark.parametrize(
    "sample_name",
    [
        "enum_lab_no_os.json",
        "enum_lab_linux_os.json",
        "enum_lab_windows_os.json",
        "enum_lab_full.json",
    ],
)
def test_focused_enum_samples_are_valid(sample_name: str):
    payload = json.loads(
        (ROOT / "data" / "samples" / sample_name).read_text(encoding="utf-8")
    )

    assert EnumInput.model_validate(payload).hosts


@pytest.mark.parametrize(
    "sample_name",
    [
        "enum_lab_no_os.json",
        "enum_lab_linux_os.json",
        "enum_lab_windows_os.json",
        "enum_lab_full.json",
    ],
)
def test_realistic_enum_samples_have_non_empty_ports(sample_name: str):
    payload = json.loads(
        (ROOT / "data" / "samples" / sample_name).read_text(encoding="utf-8")
    )
    enum_input = EnumInput.model_validate(payload)

    assert all(host.ports for host in enum_input.hosts)


def test_full_sample_has_previous_phase_metadata():
    payload = json.loads(
        (ROOT / "data" / "samples" / "enum_lab_full.json").read_text(encoding="utf-8")
    )
    enum_input = EnumInput.model_validate(payload)

    assert enum_input.scope == "local lab only"
    assert enum_input.generated_by == "phase1-phase2-enumeration"
    assert enum_input.created_at is not None
    assert enum_input.hosts[0].ports[0].state == "open"
    assert enum_input.hosts[0].ports[0].source == "nmap-service-detection"
    assert enum_input.hosts[0].vhosts == [
        "linux-lab.local",
        "admin.linux-lab.local",
        "api.linux-lab.local",
    ]
    assert enum_input.hosts[0].os.cpe == ["cpe:/o:canonical:ubuntu_linux:22.04"]
    assert enum_input.hosts[2].ports[0].cpe == ["cpe:/a:nginx:nginx:1.18.0"]
    assert "/admin" in enum_input.hosts[2].ports[0].discovered_paths
    assert "/api/v1/users" in enum_input.hosts[2].ports[0].api_endpoints


def test_enriched_lists_reject_non_string_values():
    payload = {
        "scan_id": "invalid-enriched-lists",
        "target": "authorized-lab",
        "hosts": [
            {
                "ip": "192.168.1.10",
                "vhosts": ["valid.local", 123],
                "ports": [],
            }
        ],
    }

    with pytest.raises(ValidationError):
        EnumInput.model_validate(payload)


def test_enum_without_os_still_validates():
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "no-os",
            "target": "authorized-lab",
            "hosts": [{"ip": "192.168.1.10", "ports": []}],
        }
    )

    assert enum_input.hosts[0].os is None


def test_enum_with_linux_os_validates():
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
                        "architecture": "x86_64",
                        "confidence": 92,
                        "source": "phase2-os-fingerprint",
                    },
                    "ports": [],
                }
            ],
        }
    )

    assert enum_input.hosts[0].os.kernel == "5.15.0"


def test_enum_with_windows_os_validates():
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "windows-os",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.11",
                    "os": {
                        "name": "Windows 10",
                        "version": "22H2",
                        "build": "19045",
                        "confidence": 88,
                    },
                    "ports": [],
                }
            ],
        }
    )

    assert enum_input.hosts[0].os.build == "19045"


def test_invalid_os_confidence_is_rejected():
    payload = {
        "scan_id": "invalid-os",
        "target": "authorized-lab",
        "hosts": [
            {
                "ip": "192.168.1.10",
                "os": {"name": "Ubuntu", "confidence": 101},
                "ports": [],
            }
        ],
    }

    with pytest.raises(ValidationError):
        EnumInput.model_validate(payload)


def test_enum_rejects_invalid_ip_and_port():
    payload = {
        "scan_id": "invalid-enum",
        "target": "authorized-lab",
        "hosts": [
            {
                "ip": "not-an-ip",
                "ports": [{"port": 70000, "service": "http"}],
            }
        ],
    }

    with pytest.raises(ValidationError):
        EnumInput.model_validate(payload)


def test_sample_vulnerability_output_is_valid():
    payload = {
        "scan_id": "COURSE-LAB-001",
        "summary": {
            "total": 1,
            "high": 1,
        },
        "findings": [
            {
                "finding_id": "finding-001",
                "title": "Outdated web server version",
                "severity": "high",
                "cvss": 7.5,
                "confidence": 0.9,
                "evidence": "The authorized lab service reported nginx 1.18.0.",
                "remediation": "Review and upgrade to a supported release.",
                "risk_score": 7.0,
            }
        ],
    }

    output = VulnerabilityOutput.model_validate(payload)

    assert output.summary.total == 1
    assert output.findings[0].severity is Severity.HIGH
    assert output.findings[0].source_type is SourceType.SERVICE


def test_vulnerability_output_rejects_invalid_scores():
    payload = {
        "scan_id": "COURSE-LAB-001",
        "summary": {"total": 1},
        "findings": [
            {
                "finding_id": "finding-001",
                "title": "Invalid score example",
                "severity": "low",
                "cvss": 11,
                "confidence": 2,
                "evidence": "Sample evidence.",
                "remediation": "Sample remediation.",
                "risk_score": -1,
            }
        ],
    }

    with pytest.raises(ValidationError):
        VulnerabilityOutput.model_validate(payload)


def test_agent_result_common_envelope():
    result = AgentResult(
        agent_name="version-check-agent",
        scan_id="COURSE-LAB-001",
        status=AgentStatus.SUCCESS,
        data={"findings_count": 1},
    )

    assert result.status is AgentStatus.SUCCESS
    assert result.errors == []
