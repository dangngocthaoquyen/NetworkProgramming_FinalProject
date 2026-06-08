import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.agent_result_schema import AgentResult, AgentStatus
from app.schemas.enum_schema import EnumInput
from app.schemas.vuln_schema import Severity, VulnerabilityOutput


ROOT = Path(__file__).resolve().parents[1]


def test_enum_lab_sample_is_valid():
    payload = json.loads(
        (ROOT / "data" / "samples" / "enum_lab.json").read_text(encoding="utf-8")
    )

    enum_input = EnumInput.model_validate(payload)

    assert enum_input.scan_id == "COURSE-LAB-001"
    assert str(enum_input.hosts[0].ip) == "192.168.56.10"
    assert enum_input.hosts[0].ports[1].service == "http"


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
