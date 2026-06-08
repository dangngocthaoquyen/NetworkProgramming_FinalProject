"""Finding normalization, deduplication, and merge logic."""

from app.merge.deduplicate import deduplicate_findings
from app.merge.scoring import calculate_risk_score, score_finding, severity_from_risk_score

__all__ = [
    "calculate_risk_score",
    "deduplicate_findings",
    "score_finding",
    "severity_from_risk_score",
]
