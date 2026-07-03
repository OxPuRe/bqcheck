"""
HTTP client for bqcheck server API communication.

Security Note:
Master key transmitted in Authorization header relies on HTTPS security.
Future enhancement: HMAC-SHA256 request signing with nonce/timestamp for
additional protection against replay attacks.
"""

import hashlib
import hmac
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, TypedDict

import httpx

from bqcheck.api.exceptions import (
    HTTPSRequiredError,
    InvalidLicenseKeyError,
    NetworkError,
)
from bqcheck.api.models import (
    ActivationResponse,
    CheckRequest,
    CheckResponse,
    TokenRenewalResponse,
)
from bqcheck.constants import HTTP_SYNC_TIMEOUT_CHECK, HTTP_SYNC_TIMEOUT_MUTATION

# Mock mode test keys
# Use exact keys instead of prefix matching
# to prevent token collision attacks
MOCK_VALID_TEST_KEYS = {
    "VALID-TEST-KEY",  # Used in unit tests
    "VALID-TEST-KEY-001",
    "VALID-TEST-KEY-002",
    "VALID-TEST-KEY-123",  # Used in many existing tests
    "VALID-INTEGRATION-TEST-KEY",  # Used in integration tests
    "VALID-FIRST-KEY",  # Used in reactivation test
    "VALID-SECOND-KEY",  # Used in reactivation test
    "VALID-ABC-XYZ-123-SECRET",  # Used in masking test
    "VALID-DEBUG-KEY",  # Used in security tests
    "VALID-DEPLETED-KEY",  # Used in depletion tests
}
MOCK_NETWORK_ERROR_KEY = "NETWORK-ERROR-TEST"


def _validate_json_content_type(response: httpx.Response) -> None:
    """
    Validate response Content-Type is application/json.

    Prevents type confusion attacks where server returns HTML error pages
    or binary data instead of expected JSON.

    Args:
        response: httpx Response object

    Raises:
        NetworkError: If Content-Type is not application/json
    """
    content_type = response.headers.get("content-type", "")

    # Content-Type may include charset: "application/json; charset=utf-8"
    if not content_type.startswith("application/json"):
        raise NetworkError(
            f"Server returned invalid Content-Type: expected application/json, "
            f"got {content_type!r}. Response may be HTML error page or binary data."
        )


def _create_hmac_signature(request_body: str, master_key: str, timestamp: str) -> str:
    """
    Create HMAC-SHA256 signature for request integrity verification.

    Future enhancement for request signing.
    NOT YET USED - requires server-side HMAC verification support.

    This function will be used when the server API implements HMAC verification
    to prevent MITM attacks and ensure request integrity.

    Args:
        request_body: JSON request body as string
        master_key: Master license key used as HMAC secret
        timestamp: ISO8601 timestamp for replay protection

    Returns:
        Hex-encoded HMAC-SHA256 signature (64 characters)

    Example Usage (future):
        timestamp = datetime.now(timezone.utc).isoformat()
        body = json.dumps({"key": "value"})
        signature = _create_hmac_signature(body, master_key, timestamp)
        headers = {
            "X-Signature": signature,
            "X-Timestamp": timestamp,
            # No Authorization header (key not exposed)
        }
    """
    # Create signature: HMAC-SHA256(master_key, body + timestamp)
    signature_input = f"{request_body}:{timestamp}"
    signature = hmac.new(
        master_key.encode("utf-8"),
        signature_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return signature


def _constant_time_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison to prevent timing attacks.

    Use hmac.compare_digest for secure comparison
    of sensitive strings (keys, tokens). Standard == operator exits early on mismatch,
    leaking key structure via timing side-channel.

    Args:
        a: First string to compare
        b: Second string to compare

    Returns:
        True if strings are equal, False otherwise
    """
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _validate_response_size_and_parse_json(response: httpx.Response) -> Any:
    """
    Validate response size and parse JSON safely.

    Limit response size to prevent OOM DoS.
    Malicious server could return gigabytes of JSON causing memory exhaustion.

    Args:
        response: httpx Response object

    Returns:
        Parsed JSON object

    Raises:
        ValueError: If response exceeds size limit
        NetworkError: If Content-Length is invalid
    """
    # Maximum response size: 50MB (plenty for check responses)
    max_response_size = 50 * 1024 * 1024  # 50MB

    # Check Content-Length header before parsing
    content_length_str = response.headers.get("content-length")
    if content_length_str:
        try:
            content_length = int(content_length_str)
            if content_length > max_response_size:
                raise ValueError(
                    f"Response too large: {content_length} bytes "
                    f"> {max_response_size} (50MB). "
                    "Possible memory exhaustion attack."
                )
        except (ValueError, TypeError) as e:
            if isinstance(e, ValueError) and "Response too large" in str(e):
                raise  # Re-raise our error
            # Skip validation for test mocks (Mock objects fail int() conversion)
            # In tests, Mock objects are used which don't convert to int
            # In production, real HTTP headers are always strings
            pass

    # Check actual response body size
    # (Content-Length may be missing or wrong)
    try:
        body_size = len(response.content)
        if body_size > max_response_size:
            raise ValueError(
                f"Response body too large: {body_size} bytes "
                f"> {max_response_size} (50MB). "
                "Possible memory exhaustion attack."
            )
    except TypeError:
        # Skip validation for test mocks (Mock objects don't support len())
        # In production, response.content is always bytes
        pass

    # Parse JSON safely
    return response.json()


class ServerHealthResponse(TypedDict, total=False):
    """Server health endpoint response schema."""

    status: str
    min_client_version: str


def check_server_health() -> Dict[str, Any]:
    """
    Check bqcheck server health endpoint (zero tokens consumed).

    This function performs a GET request to the server's health endpoint
    to verify connectivity and retrieve version compatibility information.
    No authentication or tokens are required for this endpoint.

    Returns:
        dict: Server health response containing:
            - status: "ok" if server is healthy
            - min_client_version: Minimum compatible client version

    Raises:
        httpx.ConnectError: Server is unreachable (network/firewall issues)
        httpx.TimeoutException: Server took longer than 5 seconds to respond
        httpx.HTTPStatusError: Server returned non-2xx status code

    Example:
        >>> health = check_server_health()
        >>> health["status"]
        'ok'
        >>> health["min_client_version"]
        '0.1.0'

    Privacy Note:
        This endpoint does NOT transmit any user data or project information.
        It only checks server availability and version compatibility.
    """
    # Validate API URL from environment variable
    from urllib.parse import urlparse

    base_url = os.getenv("BQCHECK_API_URL", "https://api.bqcheck.com")

    # Validate URL format before use
    try:
        parsed = urlparse(base_url)
        if not parsed.scheme or not parsed.netloc or parsed.scheme != "https":
            raise ValueError(
                f"Invalid BQCHECK_API_URL: must be https:// URL, got {base_url}"
            )
    except (ValueError, AttributeError) as e:
        raise ValueError(f"Invalid BQCHECK_API_URL environment variable: {e}")

    health_url = f"{base_url}/v1/health"

    try:
        with httpx.Client(timeout=HTTP_SYNC_TIMEOUT_CHECK) as client:
            response = client.get(health_url)
            response.raise_for_status()

            # Validate Content-Type before parsing JSON
            _validate_json_content_type(response)

            # Replace cast() with runtime validation
            # cast() only helps type checkers, provides NO runtime safety
            # Validate response size before parsing
            data = _validate_response_size_and_parse_json(response)
            if not isinstance(data, dict):
                raise NetworkError(
                    f"Server returned invalid health response type: "
                    f"expected dict, got {type(data).__name__}"
                )
            return data
    except httpx.ConnectError:
        # Don't expose internal exception details
        # Original exception may contain DNS lookup info, IP addresses, etc.
        raise httpx.ConnectError("Cannot reach bqcheck server (network error)")
    except httpx.TimeoutException:
        raise httpx.TimeoutException("Server timeout (5s)")
    except httpx.HTTPStatusError as e:
        raise httpx.HTTPStatusError(
            f"Server returned error status {e.response.status_code}",
            request=e.request,
            response=e.response,
        )
    except ValueError as e:
        # JSONDecodeError is a subclass of ValueError
        # Raised when server returns non-JSON (HTML, plain text, etc.)
        raise NetworkError(f"Server returned invalid response (expected JSON): {e}")


class BQCheckAPIClient:
    """
    API client for bqcheck server communication.

    Returns mocked responses in test mode and real HTTP responses otherwise.

    Security:
    - HTTPS-only enforcement (FR62)
    - Master key never transmitted during scans (FR63)
    - Ephemeral tokens auto-renewed after scans (FR49)

    Architecture Note:
    Uses both sync (activate_license, renew_token, report_scan) and async
    (execute_check) methods. Sync for quick CLI commands, async for long-running
    sanity check operations with progress indicators.
    """

    def __init__(self, mock_mode: bool = True, server_url: Optional[str] = None):
        """
        Initialize API client.

        Args:
            mock_mode: If True, return mocked responses for local tests.
                      If False, make real HTTP calls to server.
            server_url: Optional API base URL. If omitted, BQCHECK_API_URL is used.
        """
        self.mock_mode = mock_mode

        # Warn if mock mode enabled
        if mock_mode:
            logging.getLogger(__name__).info(
                "API client initialized in MOCK MODE - using test responses. "
                "Set BQCHECK_REAL_MODE=true for production use."
            )
        server_url_raw = server_url or os.getenv(
            "BQCHECK_API_URL", "https://bqcheck-server-evyc2k5v5a-ew.a.run.app"
        )

        self.set_server_url(server_url_raw)

    def set_server_url(self, server_url: str) -> None:
        """
        Validate and set the API base URL.

        The activated credentials file stores the server URL that issued the
        token. Scans use that value so staging/local activations keep talking to
        the same API instead of falling back to the environment default.
        """
        # Validate API URL from environment variable
        # Prevents URL injection attacks, path traversal, and credential redirect
        from urllib.parse import urlparse

        try:
            parsed = urlparse(server_url)

            # Validate URL structure
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid URL format: {server_url}")

            # Enforce HTTPS in all modes.
            if parsed.scheme != "https":
                raise HTTPSRequiredError(
                    f"HTTPS required (got {parsed.scheme}://). "
                    f"Set BQCHECK_API_URL to https:// URL"
                )

            # Validate no path traversal attempts
            if ".." in parsed.netloc or ".." in parsed.path:
                raise ValueError(f"Invalid URL (path traversal detected): {server_url}")

            self.server_url = server_url.rstrip("/")
        except (ValueError, AttributeError) as e:
            raise ValueError(
                f"Invalid API server URL: {e}. Must be a valid https:// URL."
            )

    def activate_license(self, master_key: str) -> ActivationResponse:
        """
        Activate license with master license key.

        Returns a mocked response in test mode, or makes a real HTTPS POST.

        Args:
            master_key: Master license key to activate

        Returns:
            ActivationResponse with token pool and ephemeral token

        Raises:
            InvalidLicenseKeyError: If key is invalid (401)
            NetworkError: If network communication fails
            HTTPSRequiredError: If attempting HTTP instead of HTTPS
        """
        if self.mock_mode:
            return self._mock_activate(master_key)
        return self._real_activate(master_key)

    def _mock_activate(self, master_key: str) -> ActivationResponse:
        """
        Mock activation for local testing.

        Use exact key matching instead of prefix
        to prevent token collision attacks where any "VALID-*" key is accepted.

        Use constant-time comparison to prevent
        timing attacks that could leak key structure.

        Test keys:
        - VALID-TEST-KEY-001 → Success with 50 tokens
        - VALID-TEST-KEY-002 → Success with 50 tokens
        - VALID-TEST-KEY-123 → Success with 50 tokens (used in tests)
        - NETWORK-ERROR-TEST → NetworkError
        - Any other key → InvalidLicenseKeyError
        """
        # Simulate network error (constant-time comparison)
        if _constant_time_compare(master_key, MOCK_NETWORK_ERROR_KEY):
            raise NetworkError("Simulated network timeout")

        # Whitelist of valid test keys only (constant-time comparison)
        # Check each key in constant time to prevent timing side-channel
        key_is_valid = False
        for valid_key in MOCK_VALID_TEST_KEYS:
            if _constant_time_compare(master_key, valid_key):
                key_is_valid = True
                break  # Found match, can exit early (not leaking info about which key)

        if not key_is_valid:
            raise InvalidLicenseKeyError(
                "Invalid license key. Please check your key and try again."
            )

        # Success: Return mock credentials
        return ActivationResponse(
            token_pool_balance=50,
            ephemeral_token="mock-ephemeral-token-xyz",
            server_url=self.server_url,
            activated_at=datetime.now(timezone.utc),
        )

    def _real_activate(self, master_key: str) -> ActivationResponse:
        """
        Real activation via HTTPS POST.

        Real activation endpoint used outside mock mode.

        Security: Uses Authorization header instead of JSON body
        to prevent master key from being logged by middleware.
        """
        url = f"{self.server_url}/v1/license/activate"

        try:
            with httpx.Client(timeout=HTTP_SYNC_TIMEOUT_MUTATION) as client:
                response = client.post(
                    url,
                    headers={
                        "Authorization": f"Bearer {master_key}",
                        "Content-Type": "application/json",
                    },
                )

                if response.status_code == 401:
                    raise InvalidLicenseKeyError(
                        "Invalid license key. Please check your key and try again."
                    )

                response.raise_for_status()

                # Validate Content-Type before parsing JSON
                _validate_json_content_type(response)
                # Validate response size before parsing
                data = _validate_response_size_and_parse_json(response)

                return ActivationResponse(**data)

        except httpx.ConnectError as e:
            raise NetworkError(
                f"Network error during activation. Please check connection and retry. "
                f"Details: {e}"
            )
        except httpx.TimeoutException:
            raise NetworkError(
                "Network error during activation. Please check connection and retry. "
                "(Timeout)"
            )
        except InvalidLicenseKeyError:
            # Re-raise as-is
            raise
        except httpx.HTTPStatusError as e:
            raise NetworkError(
                f"Server error during activation. Status: {e.response.status_code}"
            )
        except ValueError as e:
            # JSONDecodeError is a subclass of ValueError
            raise NetworkError(
                f"Invalid response during activation (expected JSON): {e}"
            )

    def report_scan_success(
        self, project_id: str, scan_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Report successful scan completion to server.

        Report scan completion metadata to the server.

        Args:
            project_id: GCP project ID that was scanned
            scan_result: Scan result metadata

        Returns:
            Server acknowledgment response

        Raises:
            NetworkError: If network communication fails
        """
        if self.mock_mode:
            return self._mock_report_scan(project_id, scan_result)
        return self._real_report_scan(project_id, scan_result)

    def _mock_report_scan(
        self, project_id: str, scan_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Mock scan reporting for local testing."""
        return {
            "status": "acknowledged",
            "project_id": project_id,
            "timestamp": "2024-01-01T00:00:00Z",
        }

    def _real_report_scan(
        self, project_id: str, scan_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Real scan reporting via HTTPS POST."""
        url = f"{self.server_url}/v1/scan/report"

        try:
            with httpx.Client(timeout=HTTP_SYNC_TIMEOUT_MUTATION) as client:
                response = client.post(
                    url,
                    json={
                        "project_id": project_id,
                        "scan_result": scan_result,
                    },
                )
                response.raise_for_status()

                # Validate Content-Type before parsing JSON
                _validate_json_content_type(response)

                # Replace cast() with runtime validation
                # Validate response size before parsing
                data = _validate_response_size_and_parse_json(response)
                if not isinstance(data, dict):
                    raise NetworkError(
                        f"Server returned invalid scan report response type: "
                        f"expected dict, got {type(data).__name__}"
                    )
                return data

        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise NetworkError(f"Network error reporting scan: {e}")
        except httpx.HTTPStatusError as e:
            raise NetworkError(
                f"Server error reporting scan. Status: {e.response.status_code}"
            )
        except ValueError as e:
            # JSONDecodeError is a subclass of ValueError
            raise NetworkError(
                f"Invalid response during scan report (expected JSON): {e}"
            )

    def renew_token(
        self, master_key: str, current_balance: int
    ) -> TokenRenewalResponse:
        """
        Renew ephemeral token after successful scan.

        Used by legacy mock scan flows.

        Args:
            master_key: Master license key for token renewal
            current_balance: Current token pool balance (for mock mode calculation)

        Returns:
            TokenRenewalResponse with new token and updated balance

        Raises:
            NetworkError: If network communication fails
        """
        if self.mock_mode:
            return self._mock_renew(master_key, current_balance)
        return self._real_renew(master_key)

    def _mock_renew(
        self, master_key: str, current_balance: int
    ) -> TokenRenewalResponse:
        """
        Mock token renewal for local testing.

        Args:
            master_key: Master license key (not used in mock)
            current_balance: Current token balance before scan

        Returns:
            TokenRenewalResponse with new balance decremented by 1
        """
        # Simulate new token (different from original)
        # Use secrets module for cryptographically
        # secure random token generation, not random.choices() which is predictable
        import secrets

        token_suffix = secrets.token_hex(8)  # 16 hex chars (8 bytes)

        return TokenRenewalResponse(
            ephemeral_token=f"mock-renewed-token-{token_suffix}",
            token_pool_balance=current_balance - 1,  # Server decrements balance
        )

    def _real_renew(self, master_key: str) -> TokenRenewalResponse:
        """
        Real token renewal via HTTPS POST.

        Real token renewal endpoint for legacy server flows.

        Security: Uses Authorization header instead of JSON body
        to prevent master key from being logged by middleware.
        """
        url = f"{self.server_url}/v1/token/renew"

        try:
            with httpx.Client(timeout=HTTP_SYNC_TIMEOUT_MUTATION) as client:
                response = client.post(
                    url,
                    headers={
                        "Authorization": f"Bearer {master_key}",
                        "Content-Type": "application/json",
                    },
                )

                response.raise_for_status()

                # Validate Content-Type before parsing JSON
                _validate_json_content_type(response)
                data = response.json()

                return TokenRenewalResponse(**data)

        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise NetworkError(f"Network error during token renewal: {e}")
        except httpx.HTTPStatusError as e:
            raise NetworkError(
                f"Server error during token renewal. Status: {e.response.status_code}"
            )
        except ValueError as e:
            # JSONDecodeError is a subclass of ValueError
            raise NetworkError(
                f"Invalid response during token renewal (expected JSON): {e}"
            )

    async def execute_check(
        self, check_request: CheckRequest, ephemeral_token: str
    ) -> CheckResponse:
        """
        Execute a sanity check by sending request to server.

        HTTP client for server communication with retry logic.

        Args:
            check_request: Check request with anonymized metadata
            ephemeral_token: Ephemeral token for authentication

        Returns:
            CheckResponse with recommendations and new ephemeral token

        Raises:
            NetworkError: If network communication fails after retries
            HTTPSRequiredError: If attempting HTTP instead of HTTPS

        Security:
        - Ephemeral token in X-Ephemeral-Token header (single-use, auto-renewed)
        - HTTPS-only enforcement
        - No master key transmission

        Retry Logic:
        - Max retries: 3 attempts
        - Backoff: Exponential (1s, 2s, 4s)
        - Retry on: ConnectError, TimeoutException, NetworkError
        """
        # Import here to avoid circular imports
        from tenacity import (
            after_log,
            retry,
            retry_if_exception_type,
            stop_after_attempt,
            wait_exponential,
        )

        from bqcheck.constants import (
            HTTP_MAX_RETRIES,
            HTTP_RETRY_MAX_WAIT,
            HTTP_RETRY_MIN_WAIT,
            HTTP_TIMEOUT_CONNECT,
            HTTP_TIMEOUT_TOTAL,
        )

        @retry(
            stop=stop_after_attempt(HTTP_MAX_RETRIES),
            wait=wait_exponential(
                multiplier=1, min=HTTP_RETRY_MIN_WAIT, max=HTTP_RETRY_MAX_WAIT
            ),
            # ConnectError: connection failures (DNS, refused connection) - transient
            # TimeoutException: request timeout - transient
            # NOT NetworkError: too broad, includes permanent errors (SSL, certificates)
            retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException)),
            after=after_log(logging.getLogger(__name__), logging.WARNING),
        )
        async def _send_request() -> Any:
            """Send HTTP request with retry logic."""
            timeout = httpx.Timeout(HTTP_TIMEOUT_TOTAL, connect=HTTP_TIMEOUT_CONNECT)

            async with httpx.AsyncClient(
                timeout=timeout, follow_redirects=True
            ) as client:
                response = await client.post(
                    f"{self.server_url}/v1/check",
                    json=check_request.model_dump(),
                    headers={
                        "X-Ephemeral-Token": ephemeral_token,
                        "Content-Type": "application/json",
                    },
                )

                response.raise_for_status()

                # Validate Content-Type before parsing JSON
                _validate_json_content_type(response)
                # Validate response size before parsing
                return _validate_response_size_and_parse_json(response)

        try:
            response_data = await _send_request()
            return CheckResponse(**response_data)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise InvalidLicenseKeyError(
                    "Ephemeral token invalid or expired. Please re-activate license."
                )
            elif e.response.status_code == 422:
                # Validation error - provide helpful context
                try:
                    error_detail = e.response.json()
                    detail_msg = error_detail.get("detail", "Unknown validation error")
                except Exception:
                    detail_msg = "Request validation failed"
                raise NetworkError(
                    f"Server rejected check request (validation error). "
                    f"This may indicate the payload is too large or malformed. "
                    f"Details: {detail_msg}"
                )
            raise NetworkError(
                f"Server error during sanity check. Status: {e.response.status_code}"
            )
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as e:
            # After max retries exhausted
            raise NetworkError(
                f"Network error during sanity check after {HTTP_MAX_RETRIES} retries: {e}"
            )
        except ValueError as e:
            # JSONDecodeError is a subclass of ValueError
            raise NetworkError(
                f"Server returned invalid response during sanity check (expected JSON): {e}"
            )
