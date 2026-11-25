import pytest

from vulnops_mcp.config import Settings
from vulnops_mcp.errors import SafetyRefusalError
from vulnops_mcp.safety import TOKEN_TTL_SECONDS, PendingApproval, SafetyGuard, args_fingerprint


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def writable(settings: Settings) -> Settings:
    return settings.model_copy(update={"vulnops_allow_writes": True})


ARGS = {"vm": "vm-web-01", "resource_group": "rg-lab"}
PREVIEW = {"action": "restart", "vm": "vm-web-01"}


def test_writes_refused_when_read_only(settings: Settings) -> None:
    guard = SafetyGuard(settings)
    assert guard.writes_enabled is False
    with pytest.raises(SafetyRefusalError, match="read-only"):
        guard.require_write("azure_restart_vm", ARGS, PREVIEW)


def test_first_call_returns_preview_and_token(writable: Settings) -> None:
    pending = SafetyGuard(writable).require_write("azure_restart_vm", ARGS, PREVIEW)
    assert isinstance(pending, PendingApproval)
    assert pending.status == "approval_required"
    assert pending.preview == PREVIEW
    assert pending.confirm_token
    assert pending.expires_in_seconds == TOKEN_TTL_SECONDS


def test_valid_token_allows_once(writable: Settings) -> None:
    guard = SafetyGuard(writable)
    pending = guard.require_write("azure_restart_vm", ARGS, PREVIEW)
    assert pending is not None
    confirmed = {**ARGS, "confirm_token": pending.confirm_token}
    assert guard.require_write("azure_restart_vm", confirmed, PREVIEW) is None
    with pytest.raises(SafetyRefusalError, match="unknown, already used or expired"):
        guard.require_write("azure_restart_vm", confirmed, PREVIEW)


def test_token_bound_to_tool_and_args(writable: Settings) -> None:
    guard = SafetyGuard(writable)
    p1 = guard.require_write("azure_restart_vm", ARGS, PREVIEW)
    assert p1 is not None
    with pytest.raises(SafetyRefusalError, match="different action"):
        guard.require_write("azure_stop_vm", {**ARGS, "confirm_token": p1.confirm_token}, PREVIEW)
    p2 = guard.require_write("azure_restart_vm", ARGS, PREVIEW)
    assert p2 is not None
    other = {"vm": "vm-db-01", "resource_group": "rg-lab", "confirm_token": p2.confirm_token}
    with pytest.raises(SafetyRefusalError, match="different action"):
        guard.require_write("azure_restart_vm", other, PREVIEW)


def test_token_expires(writable: Settings) -> None:
    clock = Clock()
    guard = SafetyGuard(writable, clock=clock)
    pending = guard.require_write("azure_restart_vm", ARGS, PREVIEW)
    assert pending is not None
    clock.now += TOKEN_TTL_SECONDS + 1
    with pytest.raises(SafetyRefusalError, match="expired"):
        guard.require_write(
            "azure_restart_vm", {**ARGS, "confirm_token": pending.confirm_token}, PREVIEW
        )


def test_fingerprint_ignores_token_and_key_order() -> None:
    a = args_fingerprint({"x": 1, "y": 2})
    assert a == args_fingerprint({"y": 2, "x": 1, "confirm_token": "t"})
    assert a != args_fingerprint({"x": 1, "y": 3})


def test_resource_group_allow_list(settings: Settings) -> None:
    guard = SafetyGuard(settings)
    assert guard.is_allowed_resource_group("RG-LAB")
    guard.check_resource_group("rg-lab")
    with pytest.raises(SafetyRefusalError, match="not in VULNOPS_ALLOWED_RESOURCE_GROUPS"):
        guard.check_resource_group("rg-prod")


def test_empty_allow_list_refuses_everything(settings: Settings) -> None:
    guard = SafetyGuard(settings.model_copy(update={"vulnops_allowed_resource_groups": []}))
    with pytest.raises(SafetyRefusalError, match="No resource groups are allowed"):
        guard.check_resource_group("rg-lab")


@pytest.mark.parametrize(
    ("name", "tags", "expected"),
    [
        ("vm-honeypot-01", None, True),
        ("WIN-HPOT", None, True),
        ("decoy-linux", {}, True),
        ("vm-web-01", {"role": "Honeypot"}, True),
        ("vm-web-01", {"VulnOps:Skip": "TRUE"}, True),
        ("vm-web-01", {"role": "web"}, False),
        ("vm-web-01", None, False),
    ],
)
def test_honeypot_detection(
    settings: Settings, name: str, tags: dict[str, str] | None, expected: bool
) -> None:
    assert SafetyGuard(settings).is_honeypot(name, tags) is expected


def test_check_not_honeypot(settings: Settings) -> None:
    guard = SafetyGuard(settings)
    guard.check_not_honeypot("vm-web-01")
    with pytest.raises(SafetyRefusalError, match="honeypot"):
        guard.check_not_honeypot("vm-honeypot-01")


def test_scan_targets_checked_against_honeypot_ips() -> None:
    SafetyGuard.check_targets_not_honeypot(["10.0.0.4"], {"10.0.0.9"})
    with pytest.raises(SafetyRefusalError, match=r"10\.0\.0\.9"):
        SafetyGuard.check_targets_not_honeypot(["10.0.0.4", " 10.0.0.9"], {"10.0.0.9"})
