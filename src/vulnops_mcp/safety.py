"""Safety rails that do not depend on the model behaving well.

- Writes are off unless ``VULNOPS_ALLOW_WRITES=true`` (write tools are not even registered).
- Every write is two-step: the first call returns a preview and a single-use
  ``confirm_token``; only a second call with that token, the same tool and the same
  arguments executes. Tokens expire after 5 minutes.
- Only resource groups in ``VULNOPS_ALLOWED_RESOURCE_GROUPS`` are visible or actionable.
- Honeypot VMs (name patterns, tags, IPs) are never scanned, changed or isolated.
"""

import hashlib
import json
import secrets
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any

from pydantic import BaseModel

from vulnops_mcp.config import Settings
from vulnops_mcp.errors import SafetyRefusalError

TOKEN_TTL_SECONDS = 300
CONFIRM_TOKEN_ARG = "confirm_token"  # noqa: S105 (argument name, not a secret)
HONEYPOT_TAGS = {("vulnops:skip", "true"), ("role", "honeypot")}

Clock = Callable[[], float]


class PendingApproval(BaseModel):
    """Returned by a write tool instead of acting, until the user approves."""

    status: str = "approval_required"
    tool: str
    preview: dict[str, Any]
    confirm_token: str
    expires_in_seconds: int = TOKEN_TTL_SECONDS
    instructions: str = (
        "Nothing has been changed. Show this preview to the user. Only if they explicitly "
        "approve, call the same tool again with the same arguments plus this confirm_token."
    )


def args_fingerprint(args: Mapping[str, Any]) -> str:
    """Stable hash of a tool's arguments, ignoring the confirm token itself."""
    clean = {k: v for k, v in args.items() if k != CONFIRM_TOKEN_ARG}
    raw = json.dumps(clean, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass(frozen=True)
class _Grant:
    tool: str
    fingerprint: str
    expires_at: float


class SafetyGuard:
    def __init__(self, settings: Settings, clock: Clock = time.monotonic) -> None:
        self._settings = settings
        self._clock = clock
        self._grants: dict[str, _Grant] = {}
        self._allowed_rgs = {rg.lower() for rg in settings.vulnops_allowed_resource_groups}
        self._patterns = [p.lower() for p in settings.vulnops_honeypot_name_patterns]

    # ---- writes -------------------------------------------------------------------

    @property
    def writes_enabled(self) -> bool:
        return self._settings.vulnops_allow_writes

    def require_write(
        self, tool: str, args: Mapping[str, Any], preview: dict[str, Any]
    ) -> PendingApproval | None:
        """Gate a write.

        Returns a ``PendingApproval`` (the tool must return it and do nothing) when no
        token was given. Returns ``None`` when a valid token was given (proceed).
        Raises ``SafetyRefusalError`` when writes are disabled or the token is invalid.
        """
        if not self.writes_enabled:
            raise SafetyRefusalError(
                f"{tool} is a write action and the server is read-only "
                "(VULNOPS_ALLOW_WRITES=false).",
                service="safety",
            )
        self._purge_expired()
        fingerprint = args_fingerprint(args)
        token = args.get(CONFIRM_TOKEN_ARG)
        if not token:
            new_token = secrets.token_urlsafe(16)
            self._grants[new_token] = _Grant(tool, fingerprint, self._clock() + TOKEN_TTL_SECONDS)
            return PendingApproval(tool=tool, preview=preview, confirm_token=new_token)
        grant = self._grants.pop(str(token), None)
        if grant is None:
            raise SafetyRefusalError(
                "confirm_token is unknown, already used or expired. Call the tool again "
                "without a token to get a fresh preview.",
                service="safety",
            )
        if grant.tool != tool or grant.fingerprint != fingerprint:
            raise SafetyRefusalError(
                "confirm_token was issued for a different action or different arguments. "
                "Nothing was changed.",
                service="safety",
            )
        return None

    def _purge_expired(self) -> None:
        now = self._clock()
        for tok in [t for t, g in self._grants.items() if g.expires_at <= now]:
            del self._grants[tok]

    # ---- scope --------------------------------------------------------------------

    def is_allowed_resource_group(self, resource_group: str) -> bool:
        return resource_group.lower() in self._allowed_rgs

    def check_resource_group(self, resource_group: str) -> None:
        if not self._allowed_rgs:
            raise SafetyRefusalError(
                "No resource groups are allowed. Set VULNOPS_ALLOWED_RESOURCE_GROUPS in .env.",
                service="safety",
            )
        if not self.is_allowed_resource_group(resource_group):
            raise SafetyRefusalError(
                f"Resource group '{resource_group}' is not in VULNOPS_ALLOWED_RESOURCE_GROUPS.",
                service="safety",
            )

    # ---- honeypots ----------------------------------------------------------------

    def is_honeypot(self, name: str, tags: Mapping[str, str] | None = None) -> bool:
        lowered = name.lower()
        if any(fnmatch(lowered, p) for p in self._patterns):
            return True
        for key, value in (tags or {}).items():
            if (key.lower(), str(value).lower()) in HONEYPOT_TAGS:
                return True
        return False

    def check_not_honeypot(self, name: str, tags: Mapping[str, str] | None = None) -> None:
        if self.is_honeypot(name, tags):
            raise SafetyRefusalError(
                f"'{name}' is a honeypot VM. It is never scanned, changed or isolated.",
                service="safety",
            )

    @staticmethod
    def check_targets_not_honeypot(targets: Iterable[str], honeypot_addresses: set[str]) -> None:
        """Refuse scan targets that are honeypot IPs or hostnames."""
        lowered = {a.lower() for a in honeypot_addresses}
        blocked = sorted({t for t in targets if t.strip().lower() in lowered})
        if blocked:
            raise SafetyRefusalError(
                f"Scan targets include honeypot addresses: {blocked}. Remove them.",
                service="safety",
            )
