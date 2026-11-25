"""``vulnops_whoami``: test every upstream service separately and report errors verbatim.

Each check is independent, so one failing service never hides the result of another.
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from vulnops_mcp import auth
from vulnops_mcp.clients.base import ApiClient
from vulnops_mcp.config import Settings
from vulnops_mcp.errors import VulnOpsError

ARM_BASE = "https://management.azure.com"
LOG_ANALYTICS_BASE = "https://api.loganalytics.io"
SUBSCRIPTIONS_API = "2022-12-01"
WORKSPACES_API = "2023-09-01"

Status = Literal["ok", "error", "not_configured"]


class ServiceCheck(BaseModel):
    service: str
    status: Status
    detail: dict[str, Any] = Field(default_factory=dict)
    error: dict[str, Any] | None = None


class WhoAmI(BaseModel):
    signed_in_as: dict[str, Any]
    overall: Literal["ok", "partial", "failed"]
    services: dict[str, ServiceCheck]


class _Checker:
    def __init__(
        self,
        settings: Settings,
        tokens: auth.TokenProvider,
        transport: httpx.AsyncBaseTransport | None,
    ) -> None:
        self.settings = settings
        self.tokens = tokens
        self.transport = transport
        self.identity: dict[str, Any] = {}

    def _bearer(self, scope: str) -> Callable[[], Awaitable[dict[str, str]]]:
        async def headers() -> dict[str, str]:
            token = await self.tokens.get_token(scope)
            if not self.identity:
                self.identity = auth.token_identity(token)
            return {"Authorization": f"Bearer {token}"}

        return headers

    def _client(self, service: str, base: str, scope: str) -> ApiClient:
        return ApiClient(service, base, self._bearer(scope), transport=self.transport)

    async def arm(self) -> ServiceCheck:
        client = self._client("arm", ARM_BASE, auth.ARM_SCOPE)
        try:
            body = await client.get("/subscriptions", params={"api-version": SUBSCRIPTIONS_API})
        finally:
            await client.aclose()
        visible = {
            s["subscriptionId"]: {"name": s.get("displayName"), "state": s.get("state")}
            for s in body.get("value", [])
        }
        configured = self.settings.subscription_ids
        missing = [sid for sid in configured if sid not in visible]
        detail: dict[str, Any] = {
            "subscriptions_visible": [{"id": k, **v} for k, v in visible.items()],
            "subscriptions_configured": configured,
        }
        if missing:
            return ServiceCheck(
                service="arm",
                status="error",
                detail=detail,
                error={"message": f"Configured subscriptions not visible to this login: {missing}"},
            )
        if not configured:
            detail["hint"] = "Set AZURE_SUBSCRIPTION_IDS in .env to the subscriptions to manage."
        return ServiceCheck(service="arm", status="ok", detail=detail)

    async def log_analytics(self) -> ServiceCheck:
        workspace = self.settings.log_analytics_workspace_id
        if not workspace:
            discovered = await self._discover_workspaces()
            return ServiceCheck(
                service="log_analytics",
                status="not_configured",
                detail={
                    "hint": "Set LOG_ANALYTICS_WORKSPACE_ID (the workspace 'customer_id').",
                    "workspaces_found": discovered,
                },
            )
        client = self._client("log_analytics", LOG_ANALYTICS_BASE, auth.LOG_ANALYTICS_SCOPE)
        try:
            body = await client.post(
                f"/v1/workspaces/{workspace}/query", json={"query": "print ok=1"}, retry=True
            )
        finally:
            await client.aclose()
        rows = body.get("tables", [{}])[0].get("rows", [])
        return ServiceCheck(
            service="log_analytics",
            status="ok",
            detail={"workspace_id": workspace, "test_query_rows": len(rows)},
        )

    async def _discover_workspaces(self) -> list[dict[str, Any]] | dict[str, Any]:
        client = self._client("arm", ARM_BASE, auth.ARM_SCOPE)
        found: list[dict[str, Any]] = []
        try:
            for sid in self.settings.subscription_ids:
                body = await client.get(
                    f"/subscriptions/{sid}/providers/Microsoft.OperationalInsights/workspaces",
                    params={"api-version": WORKSPACES_API},
                )
                for ws in body.get("value", []):
                    rid = ws.get("id", "")
                    parts = rid.split("/")
                    found.append(
                        {
                            "name": ws.get("name"),
                            "customer_id": ws.get("properties", {}).get("customerId"),
                            "resource_group": parts[4] if len(parts) > 4 else None,
                            "subscription_id": sid,
                        }
                    )
        except VulnOpsError as exc:
            return {"discovery_error": exc.to_dict()}
        finally:
            await client.aclose()
        return found

    async def defender(self) -> ServiceCheck:
        client = self._client("defender", self.settings.defender_base_url, auth.DEFENDER_SCOPE)
        try:
            body = await client.get("/api/machines", params={"$top": 1})
        finally:
            await client.aclose()
        return ServiceCheck(
            service="defender",
            status="ok",
            detail={"machines_returned": len(body.get("value", []))},
        )

    async def tenable(self) -> ServiceCheck:
        if not self.settings.tenable_configured:
            return ServiceCheck(
                service="tenable",
                status="not_configured",
                detail={"hint": "Set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in .env."},
            )
        headers = auth.tenable_headers(self.settings)

        async def tenable_auth() -> dict[str, str]:
            return headers

        client = ApiClient(
            "tenable", self.settings.tenable_base_url, tenable_auth, transport=self.transport
        )
        try:
            body = await client.get("/session")
        finally:
            await client.aclose()
        return ServiceCheck(
            service="tenable",
            status="ok",
            detail={"user": body.get("username"), "name": body.get("name")},
        )


async def _guard(name: str, check: Callable[[], Awaitable[ServiceCheck]]) -> ServiceCheck:
    try:
        return await check()
    except VulnOpsError as exc:
        return ServiceCheck(service=name, status="error", error=exc.to_dict())


async def run_whoami(
    settings: Settings,
    tokens: auth.TokenProvider,
    transport: httpx.AsyncBaseTransport | None = None,
) -> WhoAmI:
    checker = _Checker(settings, tokens, transport)
    names = ["arm", "log_analytics", "defender", "tenable"]
    results = await asyncio.gather(
        _guard("arm", checker.arm),
        _guard("log_analytics", checker.log_analytics),
        _guard("defender", checker.defender),
        _guard("tenable", checker.tenable),
    )
    services = dict(zip(names, results, strict=True))
    statuses = {r.status for r in results}
    overall: Literal["ok", "partial", "failed"]
    if statuses == {"ok"}:
        overall = "ok"
    elif "ok" in statuses:
        overall = "partial"
    else:
        overall = "failed"
    return WhoAmI(signed_in_as=checker.identity, overall=overall, services=services)
