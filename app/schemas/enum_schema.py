"""Schemas for validated Phase 2 enumeration input."""

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


class Host(EnumBaseModel):
    """A host and its enumerated services."""

    ip: IPv4Address | IPv6Address
    hostname: str | None = None
    ports: list[Port] = Field(default_factory=list)


class EnumInput(EnumBaseModel):
    """Top-level enumeration document consumed by Phase 3."""

    scan_id: str = Field(min_length=1)
    target: str = Field(min_length=1)
    hosts: list[Host] = Field(min_length=1)
