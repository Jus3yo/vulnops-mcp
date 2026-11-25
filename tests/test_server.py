from vulnops_mcp.config import Settings
from vulnops_mcp.server import build_server
from vulnops_mcp.tools.meta import server_info


async def test_server_registers_meta_tool(settings: Settings) -> None:
    server = build_server(settings)
    tools = await server.list_tools()
    assert "vulnops_server_info" in {t.name for t in tools}


def test_server_info_payload(settings: Settings) -> None:
    info = server_info(settings)
    assert info["writes_enabled"] is False
    assert info["allowed_resource_groups"] == ["rg-lab"]
    assert info["auth"].startswith("azure-cli")


async def test_call_server_info_tool(settings: Settings) -> None:
    server = build_server(settings)
    result = await server.call_tool("vulnops_server_info", {})
    assert "vulnops-mcp" in str(result)
