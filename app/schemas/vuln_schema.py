"""Schemas for normalized vulnerability scanning output."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class VulnBaseModel(BaseModel):
    """Base model that rejects unexpected vulnerability fields."""

    model_config = ConfigDict(extra="forbid")


class Severity(StrEnum):
    """Supported normalized vulnerability severities."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceType(StrEnum):
    """Origin category of a normalized vulnerability finding."""

    SERVICE = "service"
    OS = "os"
    WEB_TEMPLATE = "web-template"


class Finding(VulnBaseModel):
    """A single normalized vulnerability finding."""

    finding_id: str = Field(min_length=1)
    template_id: str | None = None
    cve_id: str | None = None
    title: str = Field(min_length=1)
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    source_agents: list[str] = Field(default_factory=list)
    source_type: SourceType = SourceType.SERVICE
    match_method: str | None = None
    validation_required: bool = False
    severity: Severity
    cvss: float | None = Field(default=None, ge=0, le=10)
    confidence: float = Field(ge=0, le=1)
    evidence: str = Field(min_length=1)
    references: list[str] = Field(default_factory=list)
    remediation: str = Field(min_length=1)
    risk_score: float = Field(ge=0, le=100)


class VulnerabilitySummary(VulnBaseModel):
    """Aggregate counts for a vulnerability scan."""

    total: int = Field(ge=0)
    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)


class VulnerabilityOutput(VulnBaseModel):
    """Top-level normalized vulnerability scan output."""

    scan_id: str = Field(min_length=1)
    summary: VulnerabilitySummary
    findings: list[Finding] = Field(default_factory=list)
