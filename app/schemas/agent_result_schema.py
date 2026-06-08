"""Common result envelope returned by Phase 3 agents."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AgentStatus(StrEnum):
    """Execution state of an agent."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class AgentResult(BaseModel):
    """Common agent result with optional structured output."""

    model_config = ConfigDict(extra="forbid")

    agent_name: str = Field(min_length=1)
    scan_id: str = Field(min_length=1)
    status: AgentStatus
    message: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
