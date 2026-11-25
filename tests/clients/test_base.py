import httpx
import pytest
import respx

from vulnops_mcp.clients.base import ApiClient
from vulnops_mcp.errors import (
    AuthError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitedError,
    UpstreamError,
)

BASE = "https://api.example.test"


async def _headers() -> dict[str, str]:
    return {"Authorization": "Bearer t"}


async def _nosleep(_: float) -> None:
    return None


def _client() -> ApiClient:
    return ApiClient("svc", BASE, _headers, sleep=_nosleep)


@respx.mock
async def test_get_success_sends_auth_header() -> None:
    route = respx.get(f"{BASE}/x").mock(return_value=httpx.Response(200, json={"a": 1}))
    c = _client()
    assert await c.get("/x") == {"a": 1}
    assert route.calls.last.request.headers["Authorization"] == "Bearer t"
    await c.aclose()


@respx.mock
async def test_empty_body_returns_none() -> None:
    respx.post(f"{BASE}/x").mock(return_value=httpx.Response(204))
    assert await _client().post("/x") is None


@pytest.mark.parametrize(
    ("status", "cls"),
    [
        (401, AuthError),
        (403, PermissionDeniedError),
        (404, NotFoundError),
        (400, UpstreamError),
    ],
)
@respx.mock
async def test_error_mapping_keeps_upstream_message(status: int, cls: type[Exception]) -> None:
    respx.get(f"{BASE}/x").mock(
        return_value=httpx.Response(
            status, json={"error": {"code": "SomeCode", "message": "Exact upstream text"}}
        )
    )
    with pytest.raises(cls) as info:
        await _client().get("/x")
    err = info.value
    assert err.message == "Exact upstream text"  # type: ignore[attr-defined]
    assert err.code == "SomeCode"  # type: ignore[attr-defined]
    assert err.status_code == status  # type: ignore[attr-defined]


@respx.mock
async def test_error_plain_text_and_string_error() -> None:
    respx.get(f"{BASE}/t").mock(return_value=httpx.Response(500, text="boom"))
    respx.get(f"{BASE}/s").mock(return_value=httpx.Response(400, json={"error": "bad thing"}))
    respx.get(f"{BASE}/l").mock(return_value=httpx.Response(400, json=["odd"]))
    c = ApiClient("svc", BASE, _headers, sleep=_nosleep, max_retries=0)
    with pytest.raises(UpstreamError, match="boom"):
        await c.get("/t")
    with pytest.raises(UpstreamError, match="bad thing"):
        await c.get("/s")
    with pytest.raises(UpstreamError, match="odd"):
        await c.get("/l")


@respx.mock
async def test_get_retries_on_429_then_succeeds() -> None:
    delays: list[float] = []

    async def record(d: float) -> None:
        delays.append(d)

    respx.get(f"{BASE}/x").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "2"}),
            httpx.Response(503, headers={"Retry-After": "soon"}),
            httpx.Response(200, json={}),
        ]
    )
    c = ApiClient("svc", BASE, _headers, sleep=record)
    assert await c.get("/x") == {}
    assert delays == [2.0, 2.0]  # Retry-After honoured, then backoff 2**1


@respx.mock
async def test_retries_exhausted_raises_rate_limited() -> None:
    respx.get(f"{BASE}/x").mock(return_value=httpx.Response(429, json={"message": "slow down"}))
    with pytest.raises(RateLimitedError, match="slow down"):
        await _client().get("/x")


@respx.mock
async def test_post_is_not_retried_by_default() -> None:
    route = respx.post(f"{BASE}/x").mock(return_value=httpx.Response(503))
    with pytest.raises(UpstreamError):
        await _client().post("/x")
    assert route.call_count == 1


@respx.mock
async def test_network_error_becomes_upstream_error() -> None:
    respx.get(f"{BASE}/x").mock(side_effect=httpx.ConnectError("no route"))
    with pytest.raises(UpstreamError, match="ConnectError"):
        await _client().get("/x")
