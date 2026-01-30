"""API-specific exceptions for bqaudit server communication."""


class BQAuditAPIError(Exception):
    """Base exception for all bqaudit API errors."""

    pass


class InvalidLicenseKeyError(BQAuditAPIError):
    """Raised when server returns 401 for invalid license key."""

    pass


class NetworkError(BQAuditAPIError):
    """Raised when network communication fails."""

    pass


class HTTPSRequiredError(BQAuditAPIError):
    """Raised when attempting to use HTTP instead of HTTPS."""

    pass
