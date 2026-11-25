"""Typed configuration loaded from the environment and a local ``.env`` file."""

from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    """All runtime settings. Secrets are only ever read from env / ``.env``."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Azure (auth uses the operator's own `az login`)
    azure_tenant_id: str | None = None
    # One or more subscriptions (comma-separated). AZURE_SUBSCRIPTION_ID is also accepted.
    azure_subscription_ids: Annotated[list[str], NoDecode] = Field(default_factory=list)
    azure_subscription_id: str | None = None

    # Log Analytics / Sentinel
    log_analytics_workspace_id: str | None = None
    sentinel_resource_group: str | None = None
    sentinel_workspace_name: str | None = None

    # Tenable
    tenable_base_url: str = "https://cloud.tenable.com"
    tenable_access_key: str | None = Field(default=None, repr=False)
    tenable_secret_key: str | None = Field(default=None, repr=False)

    # Defender for Endpoint
    defender_base_url: str = "https://api.securitycenter.microsoft.com"

    # Safety
    vulnops_allow_writes: bool = False
    vulnops_allowed_resource_groups: Annotated[list[str], NoDecode] = Field(default_factory=list)
    vulnops_honeypot_name_patterns: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["*honeypot*", "*hpot*", "*decoy*"]
    )
    vulnops_audit_log: str = "logs/audit.jsonl"
    vulnops_log_level: str = "INFO"

    @field_validator(
        "azure_subscription_ids",
        "vulnops_allowed_resource_groups",
        "vulnops_honeypot_name_patterns",
        mode="before",
    )
    @classmethod
    def _csv(cls, value: object) -> object:
        return _split_csv(value)

    @property
    def subscription_ids(self) -> list[str]:
        """All configured subscriptions, de-duplicated, in order."""
        ids = [*self.azure_subscription_ids]
        if self.azure_subscription_id:
            ids.append(self.azure_subscription_id.strip())
        return list(dict.fromkeys(i for i in ids if i))

    @property
    def tenable_configured(self) -> bool:
        return bool(self.tenable_access_key and self.tenable_secret_key)

    def enabled_services(self) -> dict[str, bool]:
        """Which integrations have enough configuration to be attempted."""
        return {
            "azure": bool(self.subscription_ids),
            "tenable": self.tenable_configured,
            "defender": True,  # only needs the operator's az login
            "sentinel": self.log_analytics_workspace_id is not None,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
