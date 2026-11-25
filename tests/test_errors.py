import pytest

from vulnops_mcp import errors


@pytest.mark.parametrize(
    "cls",
    [
        errors.AuthError,
        errors.PermissionDeniedError,
        errors.NotFoundError,
        errors.RateLimitedError,
        errors.UpstreamError,
        errors.SafetyRefusalError,
    ],
)
def test_all_errors_are_vulnops_errors(cls: type[errors.VulnOpsError]) -> None:
    assert issubclass(cls, errors.VulnOpsError)
    assert isinstance(cls.hint, str)


def test_auth_error_hint_mentions_az_login() -> None:
    assert "az login" in errors.AuthError.hint
