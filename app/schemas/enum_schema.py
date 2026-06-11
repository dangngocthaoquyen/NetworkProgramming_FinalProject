"""Schemas for validated Phase 2 enumeration input."""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field


class EnumBaseModel(BaseModel):
    """Base model that rejects unexpected enumeration fields."""

    model_config = ConfigDict(extra="forbid")


class Port(EnumBaseModel):
    """An enumerated network service."""

    port: int = Field(ge=1, le=65535)
    protocol: str = Field(default="tcp", min_length=1)
    service: str = Field(min_length=1)
    product: str | None = None
    version: str | None = None
    url: AnyHttpUrl | None = None
    state: str | None = None
    source: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=100)
    banner: str | None = None
    vhost: str | None = None
    cpe: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    discovered_paths: list[str] = Field(default_factory=list)
    api_endpoints: list[str] = Field(default_factory=list)


class OperatingSystem(EnumBaseModel):
    """Optional host-level operating-system fingerprint from earlier phases."""

    name: str | None = None
    version: str | None = None
    kernel: str | None = None
    build: str | None = None
    architecture: str | None = None
    patch_level: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=100)
    source: str | None = None
    cpe: list[str] = Field(default_factory=list)


class Host(EnumBaseModel):
    """A host and its enumerated services."""

    ip: IPv4Address | IPv6Address
    hostname: str | None = None
    vhosts: list[str] = Field(default_factory=list)
    os: OperatingSystem | None = None
    ports: list[Port] = Field(default_factory=list)


class EnumInput(EnumBaseModel):
    """Top-level enumeration document consumed by Phase 3."""

    scan_id: str = Field(min_length=1)
    target: str = Field(min_length=1)
    scope: str | None = None
    generated_by: str | None = None
    created_at: datetime | None = None
    hosts: list[Host] = Field(min_length=1)
