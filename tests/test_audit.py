import json
from pathlib import Path
from typing import Any

import pytest

from vulnops_mcp.audit import REDACTED, AuditLog, redact
from vulnops_mcp.errors import SafetyRefusalError, UpstreamError


def _lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_redact_by_key_and_value() -> None:
    data = {
        "confirm_token": "abc",
        "Tenable-Secret-Key": "s",
        "nested": [{"Authorization": "Bearer xyz"}, "header accessKey=AK1;secretKey=SK1"],
        "note": "token eyJhbGciOi.eyJzdWIiOi.sig here",
        "count": 3,
        "pair": ("Bearer abc", 1),
    }
    out = redact(data)
    assert out["confirm_token"] == REDACTED
    assert out["Tenable-Secret-Key"] == REDACTED
    assert out["nested"][0]["Authorization"] == REDACTED
    assert "AK1" not in out["nested"][1] and "SK1" not in out["nested"][1]
    assert "eyJ" not in out["note"]
    assert out["count"] == 3
    assert out["pair"] == [REDACTED, 1]


def test_sync_tool_success_recorded(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "sub" / "audit.jsonl", run_id="run1")

    def tool(vm: str, confirm_token: str | None = None) -> dict[str, str]:
        return {"vm": vm}

    wrapped = log.wrap("azure_get_vm", tool)
    assert wrapped("vm-1", confirm_token="secret-token") == {"vm": "vm-1"}
    (entry,) = _lines(log.path)
    assert entry["run_id"] == "run1"
    assert entry["tool"] == "azure_get_vm"
    assert entry["outcome"] == "ok"
    assert entry["args"] == {"vm": "vm-1", "confirm_token": REDACTED}
    assert entry["error"] is None


async def test_async_tool_outcomes(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")

    async def pending() -> dict[str, str]:
        return {"status": "approval_required"}

    async def refused() -> None:
        raise SafetyRefusalError("honeypot")

    async def upstream() -> None:
        raise UpstreamError("boom", status_code=500)

    async def crash() -> None:
        raise ValueError("bad")

    await log.wrap("w", pending)()
    for fn in (refused, upstream, crash):
        with pytest.raises(Exception):  # noqa: B017
            await log.wrap("w", fn)()
    outcomes = [(e["outcome"], (e["error"] or {}).get("message")) for e in _lines(log.path)]
    assert outcomes == [
        ("approval_required", None),
        ("refused", "honeypot"),
        ("error", "boom"),
        ("error", "bad"),
    ]


def test_sync_tool_error_recorded(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")

    def tool() -> None:
        raise UpstreamError("nope")

    with pytest.raises(UpstreamError):
        log.wrap("t", tool)()
    assert _lines(log.path)[0]["outcome"] == "error"


def test_bad_arguments_still_recorded(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")

    def tool(a: int) -> int:
        return a

    with pytest.raises(TypeError):
        log.wrap("t", tool)(1, 2, extra=3)
    assert _lines(log.path)[0]["args"] == {"extra": 3}


def test_unwritable_log_does_not_break_tool(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    log = AuditLog(blocker / "audit.jsonl")  # parent is a file -> OSError
    assert log.wrap("t", lambda: 1)() == 1
