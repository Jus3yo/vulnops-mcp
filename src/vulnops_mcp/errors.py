"""Error hierarchy. Tools turn these into clear messages with a hint for the operator."""


class VulnOpsError(Exception):
    """Base class for all errors raised by this server.

    ``status_code``, ``code`` and ``message`` keep the upstream error verbatim so the
    operator sees exactly what Azure / Tenable / Defender said.
    """

    hint: str = ""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        service: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        self.service = service

    def to_dict(self) -> dict[str, object]:
        return {
            "type": type(self).__name__,
            "status_code": self.status_code,
            "code": self.code,
            "message": self.message,
            "hint": self.hint,
        }


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
