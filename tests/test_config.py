import pytest

from vulnops_mcp.config import Settings


def test_defaults_are_read_only(settings: Settings) -> None:
    assert settings.vulnops_allow_writes is False


def test_csv_env_values_are_split(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULNOPS_ALLOWED_RESOURCE_GROUPS", "rg-a, rg-b ,")
    monkeypatch.setenv("VULNOPS_HONEYPOT_NAME_PATTERNS", "*hp*")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.vulnops_allowed_resource_groups == ["rg-a", "rg-b"]
    assert s.vulnops_honeypot_name_patterns == ["*hp*"]


def test_secrets_hidden_from_repr() -> None:
    s = Settings(_env_file=None, tenable_secret_key="supersecret")  # type: ignore[call-arg]
    assert "supersecret" not in repr(s)


def test_enabled_services(settings: Settings) -> None:
    services = settings.enabled_services()
    assert services["azure"] is True
    assert services["tenable"] is False


def test_subscription_ids_merge_and_dedupe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_SUBSCRIPTION_IDS", "sub-a, sub-b")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-a")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.subscription_ids == ["sub-a", "sub-b"]
