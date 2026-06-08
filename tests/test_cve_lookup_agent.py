from pathlib import Path

from app.agents.cve_lookup_agent import CveLookupAgent
from app.schemas.agent_result_schema import AgentStatus
from app.schemas.enum_schema import EnumInput


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


def test_run_returns_common_agent_result():
    result = CveLookupAgent().run(make_enum("OpenSSH", "7.2"))

    assert result.status is AgentStatus.SUCCESS
    assert result.data["findings"][0]["finding_id"] == "CVE-2016-0777"


def test_database_error_does_not_escape_agent(tmp_path: Path):
    result = CveLookupAgent(tmp_path / "missing.json").run(
        make_enum("OpenSSH", "7.2")
    )

    assert result.status is AgentStatus.FAILED
    assert result.errors
