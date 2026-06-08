import ipaddress
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_default_config_has_safe_guardrails():
    config = yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))
    safety = config["safety"]
    scanner = config["scanner"]

    networks = [
        ipaddress.ip_network(value) for value in safety["allowed_cidrs"]
    ]

    assert safety["block_public_ip"] is True
    assert scanner["max_concurrency"] == 5
    assert scanner["enable_nuclei"] is False
    assert any(ipaddress.ip_address("127.0.0.1") in network for network in networks)
    assert any(ipaddress.ip_address("10.0.0.1") in network for network in networks)
    assert any(ipaddress.ip_address("172.16.0.1") in network for network in networks)
    assert any(ipaddress.ip_address("192.168.0.1") in network for network in networks)
    assert not any(ipaddress.ip_address("8.8.8.8") in network for network in networks)
