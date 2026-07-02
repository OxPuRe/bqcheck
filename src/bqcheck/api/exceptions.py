"""API-specific exceptions for bqcheck server communication."""


class BQCheckAPIError(Exception):
    """Base exception for all bqcheck API errors."""

    pass


class InvalidLicenseKeyError(BQCheckAPIError):
    """Raised when server returns 401 for invalid license key."""

    pass


class NetworkError(BQCheckAPIError):
    """Raised when network communication fails."""

    pass


class HTTPSRequiredError(BQCheckAPIError):
    """Raised when attempting to use HTTP instead of HTTPS."""

    pass
