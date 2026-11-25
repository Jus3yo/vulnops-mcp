import pytest

from vulnops_mcp.config import Settings
from vulnops_mcp.server import build_server
from vulnops_mcp.tools.meta import server_info


async def test_server_registers_meta_tool(settings: Settings) -> None:
    server = build_server(settings)
    tools = await server.list_tools()
    names = {t.name for t in tools}
    assert {"vulnops_server_info", "vulnops_whoami"} <= names


def test_server_info_payload(settings: Settings) -> None:
    info = server_info(settings)
    assert info["writes_enabled"] is False
    assert info["allowed_resource_groups"] == ["rg-lab"]
    assert info["auth"].startswith("azure-cli")


async def test_call_server_info_tool(settings: Settings) -> None:
    server = build_server(settings)
    result = await server.call_tool("vulnops_server_info", {})
    assert "vulnops-mcp" in str(result)


async def test_whoami_tool_uses_cli_provider(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.fakes import FakeTokens
    from vulnops_mcp.connectivity import ServiceCheck, WhoAmI
    from vulnops_mcp.tools import meta

    fake = FakeTokens()
    monkeypatch.setattr(meta, "AzureCliTokenProvider", lambda tenant: fake)

    async def fake_run(s: Settings, tokens: FakeTokens) -> WhoAmI:
        return WhoAmI(
            signed_in_as={},
            overall="ok",
            services={"arm": ServiceCheck(service="arm", status="ok")},
        )

    monkeypatch.setattr(meta, "run_whoami", fake_run)
    result = await build_server(settings).call_tool("vulnops_whoami", {})
    assert '"overall"' in str(result) or "overall" in str(result)
    assert fake.closed
