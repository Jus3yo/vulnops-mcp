"""Meta tools: information about the server itself."""

from typing import Any

from mcp.server.mcpserver import MCPServer

from vulnops_mcp import __version__
from vulnops_mcp.config import Settings


def server_info(settings: Settings) -> dict[str, Any]:
    """Build the server-info payload (kept separate from the tool for easy testing)."""
    return {
        "name": "vulnops-mcp",
        "version": __version__,
        "auth": "azure-cli (operator's own az login)",
        "writes_enabled": settings.vulnops_allow_writes,
        "allowed_resource_groups": settings.vulnops_allowed_resource_groups,
        "honeypot_name_patterns": settings.vulnops_honeypot_name_patterns,
        "services": settings.enabled_services(),
    }


def register(server: MCPServer, settings: Settings) -> None:
    @server.tool(name="vulnops_server_info")
    def vulnops_server_info() -> dict[str, Any]:
        """Show the server version, which services are configured, whether write tools
        are enabled, the allowed resource groups and the honeypot skip rules.
        Call this first in a session."""
        return server_info(settings)
