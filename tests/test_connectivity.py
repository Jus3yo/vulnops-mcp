import httpx
import respx

from tests.fakes import FAKE_SUB_A, FAKE_SUB_B, FAKE_WORKSPACE, FakeTokens
from vulnops_mcp import auth
from vulnops_mcp.config import Settings
from vulnops_mcp.connectivity import run_whoami

ARM = "https://management.azure.com"
LA = "https://api.loganalytics.io"
MDE = "https://api.securitycenter.microsoft.com"
TEN = "https://cloud.tenable.com"


def _subs(*ids: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "value": [
                {"subscriptionId": i, "displayName": f"Lab {i[:4]}", "state": "Enabled"}
                for i in ids
            ]
        },
    )


def _full(settings: Settings) -> Settings:
    return settings.model_copy(
        update={
            "azure_subscription_ids": [FAKE_SUB_A, FAKE_SUB_B],
            "azure_subscription_id": None,
            "log_analytics_workspace_id": FAKE_WORKSPACE,
            "tenable_access_key": "ak",
            "tenable_secret_key": "sk",
        }
    )


@respx.mock
async def test_all_services_ok(settings: Settings) -> None:
    respx.get(f"{ARM}/subscriptions").mock(return_value=_subs(FAKE_SUB_A, FAKE_SUB_B))
    respx.post(f"{LA}/v1/workspaces/{FAKE_WORKSPACE}/query").mock(
        return_value=httpx.Response(200, json={"tables": [{"rows": [[1]]}]})
    )
    respx.get(f"{MDE}/api/machines").mock(return_value=httpx.Response(200, json={"value": [{}]}))
    tenable = respx.get(f"{TEN}/session").mock(
        return_value=httpx.Response(200, json={"username": "student@example.com", "name": "S"})
    )
    result = await run_whoami(_full(settings), FakeTokens())
    assert result.overall == "ok"
    assert result.signed_in_as["user"] == "student@example.com"
    assert result.services["log_analytics"].detail["test_query_rows"] == 1
    assert result.services["defender"].detail["machines_returned"] == 1
    assert result.services["tenable"].detail["user"] == "student@example.com"
    assert tenable.calls.last.request.headers["X-ApiKeys"] == "accessKey=ak;secretKey=sk"


@respx.mock
async def test_defender_consent_error_reported_verbatim_others_still_run(
    settings: Settings,
) -> None:
    respx.get(f"{ARM}/subscriptions").mock(return_value=_subs(FAKE_SUB_A, FAKE_SUB_B))
    respx.post(f"{LA}/v1/workspaces/{FAKE_WORKSPACE}/query").mock(
        return_value=httpx.Response(200, json={"tables": [{"rows": []}]})
    )
    respx.get(f"{TEN}/session").mock(
        return_value=httpx.Response(401, json={"error": "Invalid Credentials"})
    )
    tokens = FakeTokens(
        {auth.DEFENDER_SCOPE: "AADSTS65001: The user or administrator has not consented"}
    )
    result = await run_whoami(_full(settings), tokens)
    assert result.overall == "partial"
    d = result.services["defender"]
    assert d.status == "error"
    assert d.error is not None
    assert d.error["message"].startswith("AADSTS65001")
    t = result.services["tenable"]
    assert t.error is not None
    assert (t.error["status_code"], t.error["message"]) == (401, "Invalid Credentials")
    assert result.services["arm"].status == "ok"


@respx.mock
async def test_missing_subscription_and_not_configured(settings: Settings) -> None:
    s = settings.model_copy(update={"azure_subscription_ids": [FAKE_SUB_B]})
    # conftest default sub is all zeros; only FAKE_SUB_A is visible
    respx.get(f"{ARM}/subscriptions").mock(return_value=_subs(FAKE_SUB_A))
    respx.get(
        f"{ARM}/subscriptions/{FAKE_SUB_B}/providers/Microsoft.OperationalInsights/workspaces"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "name": "law-lab",
                        "id": f"/subscriptions/{FAKE_SUB_B}/resourceGroups/rg-x/providers/x/workspaces/law-lab",
                        "properties": {"customerId": FAKE_WORKSPACE},
                    }
                ]
            },
        )
    )
    respx.get(
        f"{ARM}/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.OperationalInsights/workspaces"
    ).mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(f"{MDE}/api/machines").mock(
        return_value=httpx.Response(
            403, json={"error": {"code": "Forbidden", "message": "Missing role"}}
        )
    )
    result = await run_whoami(s, FakeTokens())
    assert result.overall == "failed"
    assert result.services["arm"].status == "error"
    la = result.services["log_analytics"]
    assert la.status == "not_configured"
    assert la.detail["workspaces_found"][0]["customer_id"] == FAKE_WORKSPACE
    assert la.detail["workspaces_found"][0]["resource_group"] == "rg-x"
    assert result.services["tenable"].status == "not_configured"
    assert result.services["defender"].error["code"] == "Forbidden"  # type: ignore[index]


@respx.mock
async def test_no_subscriptions_configured_gives_hint_and_discovery_error(
    settings: Settings,
) -> None:
    s = settings.model_copy(update={"azure_subscription_id": None})
    respx.get(f"{ARM}/subscriptions").mock(return_value=_subs(FAKE_SUB_A))
    respx.get(f"{MDE}/api/machines").mock(return_value=httpx.Response(200, json={"value": []}))
    result = await run_whoami(s, FakeTokens())
    assert "hint" in result.services["arm"].detail
    assert result.services["log_analytics"].detail["workspaces_found"] == []

    s2 = settings.model_copy(update={"azure_subscription_ids": [FAKE_SUB_A]})
    respx.get(
        f"{ARM}/subscriptions/{FAKE_SUB_A}/providers/Microsoft.OperationalInsights/workspaces"
    ).mock(
        return_value=httpx.Response(
            403, json={"error": {"code": "AuthorizationFailed", "message": "no"}}
        )
    )
    respx.get(
        f"{ARM}/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.OperationalInsights/workspaces"
    ).mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(f"{ARM}/subscriptions").mock(
        return_value=_subs(FAKE_SUB_A, "00000000-0000-0000-0000-000000000000")
    )
    r2 = await run_whoami(s2, FakeTokens())
    found = r2.services["log_analytics"].detail["workspaces_found"]
    assert found["discovery_error"]["code"] == "AuthorizationFailed"
