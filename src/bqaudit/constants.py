"""Exit codes and configuration constants for bqaudit CLI."""

# Exit codes following UNIX convention
EXIT_SUCCESS = 0
EXIT_NETWORK_ERROR = 1
EXIT_FILE_ERROR = 2
EXIT_AUTH_ERROR = 3
EXIT_NO_TOKENS = 4
EXIT_RATE_LIMIT = 5

# HTTP client configuration
HTTP_TIMEOUT_TOTAL = 900.0  # 15 minutes total timeout
HTTP_TIMEOUT_CONNECT = 10.0  # 10 seconds connect timeout
HTTP_MAX_RETRIES = 3
HTTP_RETRY_BACKOFF_MULTIPLIER = 1  # Exponential backoff: 1s, 2s, 4s
HTTP_RETRY_MIN_WAIT = 1  # Minimum wait time (seconds)
HTTP_RETRY_MAX_WAIT = 4  # Maximum wait time (seconds)
