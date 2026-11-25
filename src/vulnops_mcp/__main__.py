"""Entry point: ``vulnops-mcp`` or ``python -m vulnops_mcp`` (stdio transport).

``vulnops-mcp --whoami`` runs the connectivity check once and prints JSON, without
starting the MCP server. Useful for CP2 and for debugging auth.
"""

import asyncio
import json
import sys

from vulnops_mcp.server import build_server


async def _whoami() -> None:
    from vulnops_mcp.auth import AzureCliTokenProvider
    from vulnops_mcp.config import get_settings
    from vulnops_mcp.connectivity import run_whoami

    settings = get_settings()
    tokens = AzureCliTokenProvider(settings.azure_tenant_id)
    try:
        result = await run_whoami(settings, tokens)
    finally:
        await tokens.close()
    sys.stdout.write(json.dumps(result.model_dump(), indent=2) + "\n")


def main() -> None:
    if "--whoami" in sys.argv[1:]:
        asyncio.run(_whoami())
        return
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
