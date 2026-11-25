"""Error hierarchy. Tools turn these into clear messages with a hint for the operator."""


class VulnOpsError(Exception):
    """Base class for all errors raised by this server."""

    hint: str = ""


class AuthError(VulnOpsError):
    hint = "Run `az login` (and `az account set --subscription <id>`) then retry."


class PermissionDeniedError(VulnOpsError):
    hint = "Your account lacks the role or API permission for this call."


class NotFoundError(VulnOpsError):
    pass


class RateLimitedError(VulnOpsError):
    hint = "The API is throttling requests; wait and retry."


class UpstreamError(VulnOpsError):
    pass


class SafetyRefusalError(VulnOpsError):
    """Raised when the safety layer blocks an action (allow-list, honeypot, no approval)."""
