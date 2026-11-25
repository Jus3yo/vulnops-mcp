"""Append-only JSONL audit log of every tool call. Secrets are redacted before writing."""

import functools
import inspect
import json
import logging
import re
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar, cast

from vulnops_mcp.errors import SafetyRefusalError, VulnOpsError

log = logging.getLogger(__name__)

REDACTED = "[REDACTED]"
SENSITIVE_KEY_PARTS = (
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "api_key",
    "accesskey",
    "access_key",
    "authorization",
    "credential",
)
SENSITIVE_VALUE_PATTERNS = [
    re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]*"),  # JWT
    re.compile(r"(accessKey|secretKey)=[^;\s]+", re.IGNORECASE),
    re.compile(r"Bearer\s+\S+", re.IGNORECASE),
]

F = TypeVar("F", bound=Callable[..., Any])


def redact(value: Any) -> Any:
    """Recursively redact secrets by key name and by value pattern."""
    if isinstance(value, dict):
        return {
            k: REDACTED
            if any(p in str(k).lower().replace("-", "_") for p in SENSITIVE_KEY_PARTS)
            else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    if isinstance(value, str):
        for pattern in SENSITIVE_VALUE_PATTERNS:
            value = pattern.sub(REDACTED, value)
        return value
    return value


def _outcome(result: Any) -> str:
    if isinstance(result, dict) and result.get("status") == "approval_required":
        return "approval_required"
    return "ok"


class AuditLog:
    def __init__(self, path: str | Path, run_id: str | None = None) -> None:
        self.path = Path(path)
        self.run_id = run_id or uuid.uuid4().hex[:12]

    def record(
        self,
        tool: str,
        args: dict[str, Any],
        outcome: str,
        duration_ms: float,
        error: dict[str, Any] | None = None,
    ) -> None:
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "run_id": self.run_id,
            "tool": tool,
            "args": redact(args),
            "outcome": outcome,
            "duration_ms": round(duration_ms, 1),
            "error": redact(error) if error else None,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:  # never break a tool call because logging failed
            log.error("Could not write audit log %s: %s", self.path, exc)

    def wrap(self, tool: str, fn: F) -> F:
        """Wrap a (sync or async) tool function so every call is recorded."""
        sig = inspect.signature(fn)

        def bound_args(*args: Any, **kwargs: Any) -> dict[str, Any]:
            try:
                return dict(sig.bind_partial(*args, **kwargs).arguments)
            except TypeError:
                return dict(kwargs)

        def fail(exc: Exception) -> tuple[str, dict[str, Any]]:
            if isinstance(exc, VulnOpsError):
                kind = "refused" if isinstance(exc, SafetyRefusalError) else "error"
                return kind, exc.to_dict()
            return "error", {"type": type(exc).__name__, "message": str(exc)}

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                start = time.perf_counter()
                call_args = bound_args(*args, **kwargs)
                try:
                    result = await fn(*args, **kwargs)
                except Exception as exc:
                    outcome, err = fail(exc)
                    self.record(tool, call_args, outcome, _ms(start), err)
                    raise
                self.record(tool, call_args, _outcome(result), _ms(start))
                return result

            return cast(F, async_wrapper)

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            call_args = bound_args(*args, **kwargs)
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:
                outcome, err = fail(exc)
                self.record(tool, call_args, outcome, _ms(start), err)
                raise
            self.record(tool, call_args, _outcome(result), _ms(start))
            return result

        return cast(F, sync_wrapper)


def _ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000
