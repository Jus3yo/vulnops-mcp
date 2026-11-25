import pytest

from vulnops_mcp.config import Settings


@pytest.fixture
def settings() -> Settings:
    """Settings that never read the developer's real .env."""
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        azure_subscription_id="00000000-0000-0000-0000-000000000000",
        vulnops_allowed_resource_groups=["rg-lab"],
    )
