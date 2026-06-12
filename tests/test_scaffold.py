import ipaddress
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_default_config_has_safe_guardrails():
    config = yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))
    safety = config["safety"]
    scanner = config["scanner"]
    cve_lookup = config["cve_lookup"]
    nuclei = config["nuclei"]

    networks = [
        ipaddress.ip_network(value) for value in safety["allowed_cidrs"]
    ]

    assert safety["block_public_ip"] is True
    assert scanner["max_concurrency"] == 5
    assert cve_lookup["source"] == "auto"
    assert cve_lookup["min_cvss"] == 7.0
    assert cve_lookup["nvd"]["use_cache"] is True
    assert cve_lookup["nvd"]["allow_range_matches"] is False
    assert nuclei["mode"] == "cli"
    assert nuclei["binary"] == "${NUCLEI_BINARY:-nuclei}"
    assert nuclei["severity"] == ["critical", "high"]
    assert nuclei["timeout_seconds"] == 900.0
    assert nuclei["use_mock_fallback"] is True
    assert any(ipaddress.ip_address("127.0.0.1") in network for network in networks)
    assert any(ipaddress.ip_address("10.0.0.1") in network for network in networks)
    assert any(ipaddress.ip_address("172.16.0.1") in network for network in networks)
    assert any(ipaddress.ip_address("192.168.0.1") in network for network in networks)
    assert not any(ipaddress.ip_address("8.8.8.8") in network for network in networks)
