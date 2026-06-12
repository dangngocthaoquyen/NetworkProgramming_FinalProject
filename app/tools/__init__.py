"""Safe wrappers for approved vulnerability scanning tools."""

from app.tools.nvd_client import NvdClient, NvdClientError, normalize_cpe23
from app.tools.scope_guard import ScopeGuard, ScopeViolationError

__all__ = [
    "NvdClient",
    "NvdClientError",
    "ScopeGuard",
    "ScopeViolationError",
    "normalize_cpe23",
]
