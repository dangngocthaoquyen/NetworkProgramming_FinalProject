from pathlib import Path

import pytest

from app.agents.cve_lookup_agent import CveLookupAgent
from app.schemas.agent_result_schema import AgentStatus
from app.schemas.enum_schema import EnumInput
from app.schemas.vuln_schema import SourceType
from app.tools.nvd_client import NvdClientError


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


def write_lookup_config(path: Path, source: str) -> None:
    path.write_text(
        "safety:\n"
        "  allowed_cidrs:\n"
        '    - "127.0.0.0/8"\n'
        '    - "192.168.0.0/16"\n'
        "  block_public_ip: true\n"
        "scanner:\n"
        "  max_concurrency: 5\n"
        "  enable_nuclei: false\n"
        "  enable_nuclei_mock: true\n"
        '  nuclei_mock_db: "data/nuclei_mock_db.json"\n'
        "cve_lookup:\n"
        f'  source: "{source}"\n'
        "  min_cvss: 7.0\n"
        "  nvd:\n"
        f'    cache_dir: "{(path.parent / "cache").as_posix()}"\n'
        "    use_cache: true\n"
        "    timeout_seconds: 5.0\n",
        encoding="utf-8",
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


class FakeNvdClient:
    def __init__(self, payload=None, *, error: Exception | None = None) -> None:
        self.payload = payload or {"vulnerabilities": []}
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def search_cves(self, *, cpe_name=None, keyword_search=None):
        self.calls.append((cpe_name or "", keyword_search or ""))
        if self.error is not None:
            raise self.error
        return self.payload

    def load_cached(self, *, cpe_name=None, keyword_search=None):
        self.calls.append((f"cache:{cpe_name or ''}", f"cache:{keyword_search or ''}"))
        if self.error is not None:
            return None
        return self.payload


def test_nvd_live_response_can_generate_proftpd_finding(tmp_path: Path):
    config = tmp_path / "config.yaml"
    write_lookup_config(config, "nvd_live")
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2015-3306",
                    "vulnStatus": "Modified",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write arbitrary files.",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "cvssData": {"baseScore": 10.0},
                                "baseSeverity": "HIGH",
                            }
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                    "references": [
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2015-3306"}
                    ],
                }
            }
        ]
    }
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "nvd-live",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "ports": [
                        {
                            "port": 21,
                            "service": "ftp",
                            "product": "ProFTPD",
                            "version": "1.3.5",
                            "cpe": ["cpe:/a:proftpd:proftpd:1.3.5"],
                        }
                    ],
                }
            ],
        }
    )

    findings = CveLookupAgent(
        config_path=config,
        nvd_client=FakeNvdClient(payload),
    ).lookup(enum_input)

    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2015-3306"
    assert findings[0].severity.value == "critical"
    assert findings[0].references == ["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"]
    assert "cpeName=cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*" in findings[0].evidence
    assert findings[0].match_method == "cpe-exact"
    assert findings[0].validation_required is False


def test_nvd_range_match_is_disabled_by_default(tmp_path: Path):
    config = tmp_path / "config.yaml"
    write_lookup_config(config, "nvd_live")
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-7000",
                    "vulnStatus": "Modified",
                    "descriptions": [{"lang": "en", "value": "Mock ranged record."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH"}}
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*",
                                            "versionEndIncluding": "1.3.5",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                    "references": [{"url": "https://example.test/range"}],
                }
            }
        ]
    }
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "nvd-range-disabled",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "ports": [
                        {
                            "port": 21,
                            "service": "ftp",
                            "product": "ProFTPD",
                            "version": "1.3.5",
                            "cpe": ["cpe:/a:proftpd:proftpd:1.3.5"],
                        }
                    ],
                }
            ],
        }
    )

    findings = CveLookupAgent(config_path=config, nvd_client=FakeNvdClient(payload)).lookup(enum_input)

    assert findings == []


def test_nvd_live_rejects_unconfirmed_keyword_only_match(tmp_path: Path):
    config = tmp_path / "config.yaml"
    write_lookup_config(config, "nvd_live")
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-4242",
                    "vulnStatus": "Modified",
                    "descriptions": [{"lang": "en", "value": "Mock keyword-only record."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH"},
                            }
                        ]
                    },
                    "references": [{"url": "https://example.test/cve"}],
                    "configurations": [],
                }
            }
        ]
    }
    enum_input = EnumInput.model_validate(
        {
            "scan_id": "nvd-keyword",
            "target": "authorized-lab",
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "ports": [
                        {
                            "port": 8080,
                            "service": "http",
                            "product": "Legacy Web Server",
                            "version": "1.0",
                            "cpe": [],
                        }
                    ],
                }
            ],
        }
    )

    findings = CveLookupAgent(
        config_path=config,
        nvd_client=FakeNvdClient(payload),
    ).lookup(enum_input)

    assert findings == []


def test_auto_mode_falls_back_to_mock_when_nvd_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    config = tmp_path / "config.yaml"
    db = tmp_path / "cve_mock_db.json"
    write_lookup_config(config, "auto")
    db.write_text(
        """{
  "records": [
    {
      "cve_id": "CVE-2015-3306",
      "product": "ProFTPD",
      "match_type": "exact",
      "version": "1.3.5",
      "cvss": 10.0,
      "title": "ProFTPD mod_copy arbitrary file access",
      "remediation": "Upgrade ProFTPD to a patched release.",
      "origin": "mock"
    }
  ]
}""",
        encoding="utf-8",
    )
    monkeypatch.setenv("NVD_API_KEY", "present-for-auto")

    findings = CveLookupAgent(
        db_path=db,
        config_path=config,
        nvd_client=FakeNvdClient(error=NvdClientError("nvd unavailable")),
    ).lookup(make_enum("ProFTPD", "1.3.5"))

    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2015-3306"
    assert "Fixture source: mock." in findings[0].evidence
