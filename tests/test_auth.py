import pytest
from azure.core.exceptions import ClientAuthenticationError

from tests.fakes import FAKE_TOKEN
from vulnops_mcp import auth
from vulnops_mcp.config import Settings
from vulnops_mcp.errors import AuthError


def test_token_identity_reads_claims() -> None:
    ident = auth.token_identity(FAKE_TOKEN)
    assert ident["user"] == "student@example.com"
    assert ident["tenant_id"] == "tenant-x"


@pytest.mark.parametrize("bad", ["", "not-a-jwt", "a.!!!.c"])
def test_token_identity_bad_token(bad: str) -> None:
    assert auth.token_identity(bad) == {}


def test_tenable_headers_missing_keys(settings: Settings) -> None:
    with pytest.raises(AuthError, match="TENABLE_ACCESS_KEY"):
        auth.tenable_headers(settings)


def test_tenable_headers_format(settings: Settings) -> None:
    s = settings.model_copy(update={"tenable_access_key": "ak", "tenable_secret_key": "sk"})
    assert auth.tenable_headers(s) == {"X-ApiKeys": "accessKey=ak;secretKey=sk"}


class _Tok:
    token = "abc"


class _OkCred:
    async def get_token(self, scope: str) -> _Tok:
        return _Tok()

    async def close(self) -> None:
        pass


class _BadCred(_OkCred):
    async def get_token(self, scope: str) -> _Tok:
        raise ClientAuthenticationError("AADSTS65001: consent required")


async def test_cli_provider_returns_token() -> None:
    p = auth.AzureCliTokenProvider()
    p._credential = _OkCred()  # type: ignore[assignment]
    assert await p.get_token(auth.ARM_SCOPE) == "abc"
    await p.close()


async def test_cli_provider_maps_errors_verbatim() -> None:
    p = auth.AzureCliTokenProvider()
    p._credential = _BadCred()  # type: ignore[assignment]
    with pytest.raises(AuthError, match="AADSTS65001: consent required"):
        await p.get_token(auth.DEFENDER_SCOPE)
