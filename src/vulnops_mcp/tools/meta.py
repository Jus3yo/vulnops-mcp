"""Meta tools: information about the server itself."""

from typing import Any

from mcp.server.mcpserver import MCPServer

from vulnops_mcp import __version__
from vulnops_mcp.auth import AzureCliTokenProvider
from vulnops_mcp.config import Settings
from vulnops_mcp.connectivity import run_whoami


def server_info(settings: Settings) -> dict[str, Any]:
    """Build the server-info payload (kept separate from the tool for easy testing)."""
    return {
        "name": "vulnops-mcp",
        "version": __version__,
        "auth": "azure-cli (operator's own az login)",
        "writes_enabled": settings.vulnops_allow_writes,
        "subscriptions": settings.subscription_ids,
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

    @server.tool(name="vulnops_whoami")
    async def vulnops_whoami() -> dict[str, Any]:
        """Connectivity check. Shows who you are signed in as (your az login) and tests each
        service separately: Azure Resource Manager, Log Analytics, Defender for Endpoint
        and Tenable. Each service reports ok, not_configured (with what to set) or error
        with the upstream status code and message verbatim. Read-only; no approval needed.
        Run this first, and whenever calls start failing with auth errors."""
        tokens = AzureCliTokenProvider(settings.azure_tenant_id)
        try:
            result = await run_whoami(settings, tokens)
        finally:
            await tokens.close()
        return result.model_dump()
