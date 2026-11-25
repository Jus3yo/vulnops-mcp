"""Shared async HTTP client: auth headers, timeouts, retries and verbatim error mapping."""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from vulnops_mcp.errors import (
    AuthError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitedError,
    UpstreamError,
    VulnOpsError,
)

log = logging.getLogger(__name__)

HeaderFactory = Callable[[], Awaitable[dict[str, str]]]
Sleep = Callable[[float], Awaitable[None]]

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
SAFE_METHODS = {"GET", "HEAD"}


def _extract_error(response: httpx.Response) -> tuple[str | None, str]:
    """Pull (code, message) out of the common Azure / Defender / Tenable error shapes."""
    try:
        body = response.json()
    except ValueError:
        return None, response.text[:1000] or response.reason_phrase
    if isinstance(body, dict):
        err = body.get("error", body)
        if isinstance(err, dict):
            code = err.get("code") or err.get("error")
            message = err.get("message") or err.get("error_description") or str(body)
            return (str(code) if code else None), str(message)
        if isinstance(err, str):
            return None, err
    return None, str(body)[:1000]


def map_error(response: httpx.Response, service: str) -> VulnOpsError:
    code, message = _extract_error(response)
    status = response.status_code
    cls: type[VulnOpsError]
    if status == 401:
        cls = AuthError
    elif status == 403:
        cls = PermissionDeniedError
    elif status == 404:
        cls = NotFoundError
    elif status == 429:
        cls = RateLimitedError
    else:
        cls = UpstreamError
    return cls(message, status_code=status, code=code, service=service)


class ApiClient:
    """Thin wrapper over ``httpx.AsyncClient`` used by every service client.

    Reads (GET/HEAD, or ``retry=True``) are retried on 429/5xx with ``Retry-After`` or
    exponential backoff. Writes are never retried.
    """

    def __init__(
        self,
        service: str,
        base_url: str,
        headers: HeaderFactory,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self.service = service
        self._headers = headers
        self._max_retries = max_retries
        self._sleep = sleep
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout, transport=transport)

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        retry: bool | None = None,
    ) -> Any:
        method = method.upper()
        can_retry = retry if retry is not None else method in SAFE_METHODS
        attempt = 0
        while True:
            headers = await self._headers()
            try:
                response = await self._client.request(
                    method, path, params=params, json=json, headers=headers
                )
            except httpx.HTTPError as exc:
                raise UpstreamError(f"{type(exc).__name__}: {exc}", service=self.service) from exc
            if (
                response.status_code in RETRYABLE_STATUS
                and can_retry
                and attempt < self._max_retries
            ):
                delay = self._retry_delay(response, attempt)
                log.warning(
                    "%s %s -> %s, retrying in %.1fs", method, path, response.status_code, delay
                )
                attempt += 1
                await self._sleep(delay)
                continue
            if response.is_success:
                return response.json() if response.content else None
            raise map_error(response, self.service)

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return min(float(retry_after), 60.0)
            except ValueError:
                pass
        return float(2**attempt)

    async def get(self, path: str, **kwargs: Any) -> Any:
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> Any:
        return await self.request("POST", path, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()
