"""Shared fakes. All identifiers here are fictional."""

import base64
import json

from vulnops_mcp.errors import AuthError

FAKE_SUB_A = "11111111-1111-1111-1111-111111111111"
FAKE_SUB_B = "22222222-2222-2222-2222-222222222222"
FAKE_WORKSPACE = "33333333-3333-3333-3333-333333333333"


def fake_jwt(claims: dict[str, str]) -> str:
    def enc(d: dict[str, str]) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


FAKE_TOKEN = fake_jwt(
    {"upn": "student@example.com", "name": "Test Student", "tid": "tenant-x", "oid": "obj-y"}
)


class FakeTokens:
    def __init__(self, fail_scopes: dict[str, str] | None = None) -> None:
        self.fail_scopes = fail_scopes or {}
        self.closed = False

    async def get_token(self, scope: str) -> str:
        if scope in self.fail_scopes:
            raise AuthError(self.fail_scopes[scope], service=scope)
        return FAKE_TOKEN

    async def close(self) -> None:
        self.closed = True
