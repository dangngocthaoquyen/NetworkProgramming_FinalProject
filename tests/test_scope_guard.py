import socket

import pytest

from app.tools.scope_guard import ScopeGuard, ScopeViolationError


@pytest.fixture
def scope_guard() -> ScopeGuard:
    return ScopeGuard.from_config("config.yaml")


def test_localhost_is_allowed(scope_guard: ScopeGuard):
    addresses = scope_guard.validate_hostname("localhost")

    assert str(addresses[0]) == "127.0.0.1"


def test_private_ip_is_allowed(scope_guard: ScopeGuard):
    address = scope_guard.validate_ip("192.168.1.10")

    assert str(address) == "192.168.1.10"


def test_public_ip_is_blocked(scope_guard: ScopeGuard):
    with pytest.raises(ScopeViolationError, match="Public IP is blocked"):
        scope_guard.validate_ip("8.8.8.8")


def test_public_domain_is_blocked(
    scope_guard: ScopeGuard, monkeypatch: pytest.MonkeyPatch
):
    def resolve_public_domain(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve_public_domain)

    with pytest.raises(ScopeViolationError, match="Public IP is blocked"):
        scope_guard.validate_hostname("public.example")


def test_enum_rejects_any_public_host(scope_guard: ScopeGuard):
    enum_input = {
        "scan_id": "scope-test",
        "target": "authorized-lab",
        "hosts": [
            {"ip": "192.168.1.10", "ports": []},
            {"ip": "8.8.8.8", "ports": []},
        ],
    }

    with pytest.raises(ScopeViolationError, match="Public IP is blocked"):
        scope_guard.validate_enum(enum_input)


def test_enum_allows_inventory_hostname_when_ip_is_in_scope(scope_guard: ScopeGuard):
    enum_input = {
        "scan_id": "inventory-hostname",
        "target": "authorized-lab",
        "hosts": [
            {
                "ip": "192.168.1.10",
                "hostname": "linux-lab",
                "ports": [],
            }
        ],
    }

    assert scope_guard.validate_enum(enum_input).hosts[0].hostname == "linux-lab"
