"""Credentials: the operator's own ``az login`` for Microsoft APIs, API keys for Tenable.

Nothing here logs or returns secrets. Token claims are decoded (without verification)
only to show the operator who they are signed in as.
"""

import base64
import json
from typing import Any, Protocol

from azure.core.exceptions import ClientAuthenticationError
from azure.identity.aio import AzureCliCredential

from vulnops_mcp.config import Settings
from vulnops_mcp.errors import AuthError

ARM_SCOPE = "https://management.azure.com/.default"
DEFENDER_SCOPE = "https://api.securitycenter.microsoft.com/.default"
LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"


class TokenProvider(Protocol):
    async def get_token(self, scope: str) -> str: ...

    async def close(self) -> None: ...


class AzureCliTokenProvider:
    """Gets access tokens from the operator's Azure CLI session (``az login``)."""

    def __init__(self, tenant_id: str | None = None) -> None:
        self._credential = AzureCliCredential(tenant_id=tenant_id or "")

    async def get_token(self, scope: str) -> str:
        try:
            token = await self._credential.get_token(scope)
        except ClientAuthenticationError as exc:
            raise AuthError(str(exc), service=scope) from exc
        return str(token.token)

    async def close(self) -> None:
        await self._credential.close()


def tenable_headers(settings: Settings) -> dict[str, str]:
    """``X-ApiKeys`` header for Tenable. Raises ``AuthError`` if keys are missing."""
    if not settings.tenable_configured:
        raise AuthError(
            "TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY are not set in .env",
            service="tenable",
        )
    return {
        "X-ApiKeys": (
            f"accessKey={settings.tenable_access_key};secretKey={settings.tenable_secret_key}"
        )
    }


def token_identity(token: str) -> dict[str, Any]:
    """Who a JWT access token belongs to. Display only: the signature is NOT verified."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims: dict[str, Any] = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError):
        return {}
    return {
        "user": claims.get("upn") or claims.get("unique_name") or claims.get("appid"),
        "name": claims.get("name"),
        "tenant_id": claims.get("tid"),
        "object_id": claims.get("oid"),
    }
