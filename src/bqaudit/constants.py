"""Exit codes and configuration constants for bqaudit CLI."""

from enum import IntEnum


# Exit codes following UNIX convention (Story 5.3: Using IntEnum for type safety)
class ExitCode(IntEnum):
    """CLI exit codes following UNIX conventions."""

    SUCCESS = 0
    NETWORK_ERROR = 1
    FILE_ERROR = 2
    AUTH_ERROR = 3
    NO_TOKENS = 4
    RATE_LIMIT = 5


# Legacy constants for backward compatibility
EXIT_SUCCESS = ExitCode.SUCCESS
EXIT_NETWORK_ERROR = ExitCode.NETWORK_ERROR
EXIT_FILE_ERROR = ExitCode.FILE_ERROR
EXIT_AUTH_ERROR = ExitCode.AUTH_ERROR
EXIT_NO_TOKENS = ExitCode.NO_TOKENS
EXIT_RATE_LIMIT = ExitCode.RATE_LIMIT

# HTTP client configuration
HTTP_TIMEOUT_TOTAL = 900.0  # 15 minutes total timeout
HTTP_TIMEOUT_CONNECT = 10.0  # 10 seconds connect timeout
HTTP_MAX_RETRIES = 3
HTTP_RETRY_BACKOFF_MULTIPLIER = 1  # Exponential backoff: 1s, 2s, 4s
HTTP_RETRY_MIN_WAIT = 1  # Minimum wait time (seconds)
HTTP_RETRY_MAX_WAIT = 4  # Maximum wait time (seconds)

# Audit execution configuration (Story 5.3)
GLOBAL_AUDIT_TIMEOUT_SECONDS = 1200.0  # 20 minutes global timeout for execute_audit
TIMER_CANCEL_TIMEOUT_SECONDS = 5.0  # Timeout for timer task cancellation

# HTTP client sync timeouts (Story 5.3 - Code Review Round 3, Issue #5)
HTTP_SYNC_TIMEOUT_CHECK = 5.0  # Quick operations (license check)
HTTP_SYNC_TIMEOUT_MUTATION = 10.0  # State-changing operations (activate, renew, report)

# Environment variables for real vs mock mode (Story 5.3 - Code Review Round 3, Issue #3)
ENV_VAR_REAL_MODE = "BQAUDIT_REAL_MODE"  # Controls API client mode (mock vs real server)
ENV_VAR_REAL_SCAN = "BQAUDIT_REAL_SCAN"  # Controls scan execution (simulated vs real)


# Helper functions for environment variable checks (Code Review Round 4, Issue #1 & #4)
def is_real_mode() -> bool:
    """
    Check if real mode is enabled via BQAUDIT_REAL_MODE environment variable.

    Returns:
        True if BQAUDIT_REAL_MODE=true, False otherwise (default: mock mode)
    """
    import os
    return os.getenv(ENV_VAR_REAL_MODE, "").lower() == "true"


def is_real_scan() -> bool:
    """
    Check if real scan is enabled via BQAUDIT_REAL_SCAN environment variable.

    Returns:
        True if BQAUDIT_REAL_SCAN=true, False otherwise (default: simulated scan)
    """
    import os
    return os.getenv(ENV_VAR_REAL_SCAN, "").lower() == "true"
