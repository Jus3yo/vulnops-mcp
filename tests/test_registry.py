import json
from pathlib import Path
from typing import Any

from vulnops_mcp.audit import AuditLog
from vulnops_mcp.config import Settings
from vulnops_mcp.safety import SafetyGuard
from vulnops_mcp.server import build_server
from vulnops_mcp.tools.registry import ToolContext


def _ctx(settings: Settings, tmp_path: Path) -> ToolContext:
    from mcp.server.mcpserver import MCPServer

    return ToolContext(
        server=MCPServer(name="t"),
        settings=settings,
        guard=SafetyGuard(settings),
        audit=AuditLog(tmp_path / "audit.jsonl"),
    )


def _register_demo(ctx: ToolContext) -> None:
    @ctx.write_tool("demo_restart")
    def demo_restart(vm: str, confirm_token: str | None = None) -> dict[str, Any]:
        """Demo write tool."""
        args = {"vm": vm, "confirm_token": confirm_token}
        pending = ctx.guard.require_write("demo_restart", args, {"restart": vm})
        if pending:
            return pending.model_dump()
        return {"done": vm}


async def test_write_tools_hidden_when_read_only(settings: Settings, tmp_path: Path) -> None:
    ctx = _ctx(settings, tmp_path)
    _register_demo(ctx)
    assert "demo_restart" not in {t.name for t in await ctx.server.list_tools()}


async def test_write_tool_two_step_flow_is_audited(settings: Settings, tmp_path: Path) -> None:
    ctx = _ctx(settings.model_copy(update={"vulnops_allow_writes": True}), tmp_path)
    _register_demo(ctx)
    tools = {t.name: t for t in await ctx.server.list_tools()}
    assert tools["demo_restart"].annotations.destructive_hint is True  # type: ignore[union-attr]

    first = await ctx.server.call_tool("demo_restart", {"vm": "vm-1"})
    payload = first.structured_content  # type: ignore[union-attr]
    assert payload["status"] == "approval_required"
    token = payload["confirm_token"]

    second = await ctx.server.call_tool("demo_restart", {"vm": "vm-1", "confirm_token": token})
    assert second.structured_content == {"done": "vm-1"}  # type: ignore[union-attr]

    entries = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [e["outcome"] for e in entries] == ["approval_required", "ok"]
    assert token not in (tmp_path / "audit.jsonl").read_text()


async def test_read_tools_are_audited(settings: Settings) -> None:
    await build_server(settings).call_tool("vulnops_server_info", {})
    log = Path(settings.vulnops_audit_log)
    assert json.loads(log.read_text().splitlines()[0])["tool"] == "vulnops_server_info"
