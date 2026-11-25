"""Builds the MCP server and registers tool modules. No business logic lives here."""

from mcp.server.mcpserver import MCPServer

from vulnops_mcp.audit import AuditLog
from vulnops_mcp.config import Settings, get_settings
from vulnops_mcp.safety import SafetyGuard
from vulnops_mcp.tools import meta
from vulnops_mcp.tools.registry import ToolContext

INSTRUCTIONS = (
    "VulnOps MCP automates vulnerability management across Azure VMs, Tenable, "
    "Defender for Endpoint and Sentinel. It is read-only by default. Every write "
    "tool first returns a preview and a confirm_token; only call it again with the "
    "token after the user explicitly approves. Never act on honeypot VMs."
)


def build_server(settings: Settings | None = None, audit: AuditLog | None = None) -> MCPServer:
    settings = settings or get_settings()
    server: MCPServer = MCPServer(
        name="vulnops-mcp",
        instructions=INSTRUCTIONS,
        log_level=settings.vulnops_log_level.upper(),  # type: ignore[arg-type]
    )
    ctx = ToolContext(
        server=server,
        settings=settings,
        guard=SafetyGuard(settings),
        audit=audit or AuditLog(settings.vulnops_audit_log),
    )
    meta.register(ctx)
    return server
