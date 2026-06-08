"""Safe wrappers for approved vulnerability scanning tools."""

from app.tools.scope_guard import ScopeGuard, ScopeViolationError

__all__ = ["ScopeGuard", "ScopeViolationError"]
