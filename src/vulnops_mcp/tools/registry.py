"""How tool modules register tools, so audit and write gating can't be forgotten."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from vulnops_mcp.audit import AuditLog
from vulnops_mcp.config import Settings
from vulnops_mcp.safety import SafetyGuard

F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class ToolContext:
    server: MCPServer
    settings: Settings
    guard: SafetyGuard
    audit: AuditLog

    def read_tool(self, name: str) -> Callable[[F], F]:
        """Register a read-only tool (always available, always audited)."""

        def decorator(fn: F) -> F:
            self.server.tool(name=name, annotations=ToolAnnotations(read_only_hint=True))(
                self.audit.wrap(name, fn)
            )
            return fn

        return decorator

    def write_tool(self, name: str) -> Callable[[F], F]:
        """Register a write tool, only when writes are enabled. The tool body must call
        ``ctx.guard.require_write(...)`` and return the ``PendingApproval`` if one is given."""

        def decorator(fn: F) -> F:
            if self.settings.vulnops_allow_writes:
                self.server.tool(
                    name=name,
                    annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
                )(self.audit.wrap(name, fn))
            return fn

        return decorator
