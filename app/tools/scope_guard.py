"""Validate enumeration targets against the configured authorized scope."""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from typing import Any

import yaml

from app.schemas.enum_schema import EnumInput


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeViolationError(ValueError):
    """Raised when a target falls outside the explicitly allowed scope."""


class ScopeGuard:
    """Enforce configured CIDR and public-IP restrictions before scanning."""

    def __init__(self, allowed_cidrs: list[str], block_public_ip: bool = True) -> None:
        if not allowed_cidrs:
            raise ValueError("At least one allowed CIDR is required")

        self.allowed_networks: tuple[IPNetwork, ...] = tuple(
            ipaddress.ip_network(cidr, strict=True) for cidr in allowed_cidrs
        )
        self.block_public_ip = block_public_ip

    @classmethod
    def from_config(cls, config_path: str | Path = "config.yaml") -> ScopeGuard:
        """Create a guard from the safety section of a YAML config file."""

        path = Path(config_path)
        config: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
        safety = config.get("safety")
        if not isinstance(safety, dict):
            raise ValueError("config.yaml must contain a safety mapping")

        allowed_cidrs = safety.get("allowed_cidrs")
        if not isinstance(allowed_cidrs, list) or not all(
            isinstance(cidr, str) for cidr in allowed_cidrs
        ):
            raise ValueError("safety.allowed_cidrs must be a list of CIDR strings")

        block_public_ip = safety.get("block_public_ip")
        if not isinstance(block_public_ip, bool):
            raise ValueError("safety.block_public_ip must be a boolean")

        return cls(allowed_cidrs, block_public_ip)

    def validate_ip(self, value: str | IPAddress) -> IPAddress:
        """Validate one IP address and return its parsed representation."""

        address = ipaddress.ip_address(value)

        if self.block_public_ip and address.is_global:
            raise ScopeViolationError(f"Public IP is blocked: {address}")

        if not any(address in network for network in self.allowed_networks):
            raise ScopeViolationError(f"IP is outside allowed_cidrs: {address}")

        return address

    def validate_hostname(self, hostname: str) -> tuple[IPAddress, ...]:
        """Resolve and validate every address associated with a hostname."""

        normalized = hostname.rstrip(".").lower()
        if normalized == "localhost":
            return (self.validate_ip("127.0.0.1"),)

        try:
            records = socket.getaddrinfo(
                normalized,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise ScopeViolationError(f"Hostname could not be resolved: {hostname}") from exc

        addresses = tuple(
            dict.fromkeys(ipaddress.ip_address(record[4][0]) for record in records)
        )
        if not addresses:
            raise ScopeViolationError(f"Hostname resolved to no IP addresses: {hostname}")

        for address in addresses:
            self.validate_ip(address)

        return addresses

    def validate_enum(self, enum_input: EnumInput | dict[str, Any]) -> EnumInput:
        """Validate every IP and optional hostname in an enumeration document."""

        validated = (
            enum_input
            if isinstance(enum_input, EnumInput)
            else EnumInput.model_validate(enum_input)
        )

        for host in validated.hosts:
            self.validate_ip(host.ip)

        return validated
