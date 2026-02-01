"""HTTP client for bqaudit server API communication."""

import os
from datetime import datetime, timezone
from typing import Any, Dict, TypedDict, cast

import httpx

from bqaudit.api.exceptions import (
    HTTPSRequiredError,
    InvalidLicenseKeyError,
    NetworkError,
)
from bqaudit.api.models import (
    ActivationResponse,
    TokenRenewalResponse,
    AuditRequest,
    AuditResponse,
)

# Mock mode test key prefixes (Epic 3)
MOCK_VALID_KEY_PREFIX = "VALID-"
MOCK_NETWORK_ERROR_PREFIX = "NETWORK-ERROR"


class ServerHealthResponse(TypedDict, total=False):
    """Server health endpoint response schema."""

    status: str
    min_client_version: str


def check_server_health() -> Dict[str, Any]:
    """
    Check bqaudit server health endpoint (zero tokens consumed).

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
    # Allow override via environment variable (useful for testing/dev)
    base_url = os.getenv("BQAUDIT_API_URL", "https://api.bqaudit.com")
    health_url = f"{base_url}/v1/health"

    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.get(health_url)
            response.raise_for_status()
            return cast(Dict[str, Any], response.json())
    except httpx.ConnectError as e:
        raise httpx.ConnectError(f"Cannot reach bqaudit server: {e}")
    except httpx.TimeoutException:
        raise httpx.TimeoutException("Server timeout (5s)")
    except httpx.HTTPStatusError as e:
        raise httpx.HTTPStatusError(
            f"Server returned error status {e.response.status_code}",
            request=e.request,
            response=e.response,
        )


class BQAuditAPIClient:
    """
    API client for bqaudit server communication.

    Epic 3: Returns mocked responses for testing (mock_mode=True)
    Future Epic: Switches to real HTTP calls (mock_mode=False)

    Security:
    - HTTPS-only enforcement (FR62)
    - Master key never transmitted during scans (FR63)
    - Ephemeral tokens auto-renewed after scans (FR49)
    """

    def __init__(self, mock_mode: bool = True):
        """
        Initialize API client.

        Args:
            mock_mode: If True, return mocked responses for Epic 3 testing.
                      If False, make real HTTP calls to server.
        """
        self.mock_mode = mock_mode
        self.server_url = os.getenv("BQAUDIT_API_URL", "https://api.bqaudit.com")

        # Enforce HTTPS (AC8 - FR62)
        if not self.mock_mode and not self.server_url.startswith("https://"):
            raise HTTPSRequiredError(
                f"HTTPS required for server communication. Got: {self.server_url}"
            )

    def activate_license(self, master_key: str) -> ActivationResponse:
        """
        Activate license with master license key.

        Epic 3: Returns mocked response
        Future Epic: Makes real HTTPS POST to /v1/license/activate

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
        Mock activation for Epic 3 testing.

        Test keys:
        - VALID-* → Success with 50 tokens
        - INVALID-* → InvalidLicenseKeyError
        - NETWORK-ERROR → NetworkError
        """
        # Simulate network error
        if master_key.startswith(MOCK_NETWORK_ERROR_PREFIX):
            raise NetworkError("Simulated network timeout")

        # Simulate invalid key
        if not master_key.startswith(MOCK_VALID_KEY_PREFIX):
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

        Future Epic implementation - not used in Epic 3.

        Security: Uses Authorization header instead of JSON body
        to prevent master key from being logged by middleware.
        """
        url = f"{self.server_url}/v1/license/activate"

        try:
            with httpx.Client(timeout=10.0) as client:
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
                data = response.json()

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

    def report_scan_success(
        self, project_id: str, scan_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Report successful scan completion to server.

        Used by Story 3.4 (AC1: report success to server).

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
        """Mock scan reporting for Epic 3."""
        return {
            "status": "acknowledged",
            "project_id": project_id,
            "timestamp": "2024-01-01T00:00:00Z",
        }

    def _real_report_scan(
        self, project_id: str, scan_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Real scan reporting via HTTPS POST (Future Epic)."""
        url = f"{self.server_url}/v1/scan/report"

        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(
                    url,
                    json={
                        "project_id": project_id,
                        "scan_result": scan_result,
                    },
                )
                response.raise_for_status()
                return cast(Dict[str, Any], response.json())
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise NetworkError(f"Network error reporting scan: {e}")
        except httpx.HTTPStatusError as e:
            raise NetworkError(
                f"Server error reporting scan. Status: {e.response.status_code}"
            )

    def renew_token(
        self, master_key: str, current_balance: int
    ) -> TokenRenewalResponse:
        """
        Renew ephemeral token after successful scan.

        Used by Story 3.4 (Scan Token Management & Auto-Renewal).

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
        Mock token renewal for Epic 3 testing.

        Args:
            master_key: Master license key (not used in mock)
            current_balance: Current token balance before scan

        Returns:
            TokenRenewalResponse with new balance decremented by 1
        """
        # Simulate new token (different from original)
        import random
        import string

        token_suffix = "".join(random.choices(string.ascii_lowercase, k=8))

        return TokenRenewalResponse(
            ephemeral_token=f"mock-renewed-token-{token_suffix}",
            token_pool_balance=current_balance - 1,  # Server decrements balance
        )

    def _real_renew(self, master_key: str) -> TokenRenewalResponse:
        """
        Real token renewal via HTTPS POST.

        Future Epic implementation - not used in Epic 3.

        Security: Uses Authorization header instead of JSON body
        to prevent master key from being logged by middleware.
        """
        url = f"{self.server_url}/v1/token/renew"

        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(
                    url,
                    headers={
                        "Authorization": f"Bearer {master_key}",
                        "Content-Type": "application/json",
                    },
                )

                response.raise_for_status()
                data = response.json()

                return TokenRenewalResponse(**data)

        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise NetworkError(f"Network error during token renewal: {e}")
        except httpx.HTTPStatusError as e:
            raise NetworkError(
                f"Server error during token renewal. Status: {e.response.status_code}"
            )

    async def execute_audit(
        self, audit_request: AuditRequest, ephemeral_token: str
    ) -> AuditResponse:
        """
        Execute audit by sending request to server.

        Story 5.1 - Task 2: HTTP client for server communication with retry logic.

        Args:
            audit_request: Audit request with anonymized metadata
            ephemeral_token: Ephemeral token for authentication

        Returns:
            AuditResponse with recommendations and new ephemeral token

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
            retry,
            stop_after_attempt,
            wait_exponential,
            retry_if_exception_type,
            after_log,
        )
        import logging
        from bqaudit.constants import (
            HTTP_TIMEOUT_TOTAL,
            HTTP_TIMEOUT_CONNECT,
            HTTP_MAX_RETRIES,
            HTTP_RETRY_MIN_WAIT,
            HTTP_RETRY_MAX_WAIT,
        )

        @retry(
            stop=stop_after_attempt(HTTP_MAX_RETRIES),
            wait=wait_exponential(
                multiplier=1, min=HTTP_RETRY_MIN_WAIT, max=HTTP_RETRY_MAX_WAIT
            ),
            # Story 5.3: Only retry on truly transient errors
            # ConnectError: connection failures (DNS, refused connection) - transient
            # TimeoutException: request timeout - transient
            # NOT NetworkError: too broad, includes permanent errors (SSL, certificates)
            retry=retry_if_exception_type(
                (httpx.ConnectError, httpx.TimeoutException)
            ),
            # Story 5.3: Log retry attempts for debugging
            after=after_log(logging.getLogger(__name__), logging.WARNING),
        )
        async def _send_request():
            """Send HTTP request with retry logic."""
            timeout = httpx.Timeout(HTTP_TIMEOUT_TOTAL, connect=HTTP_TIMEOUT_CONNECT)

            async with httpx.AsyncClient(
                timeout=timeout, follow_redirects=True
            ) as client:
                response = await client.post(
                    f"{self.server_url}/v1/audit",
                    json=audit_request.model_dump(),
                    headers={
                        "X-Ephemeral-Token": ephemeral_token,
                        "Content-Type": "application/json",
                    },
                )

                response.raise_for_status()
                return response.json()

        try:
            response_data = await _send_request()
            return AuditResponse(**response_data)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise InvalidLicenseKeyError(
                    "Ephemeral token invalid or expired. Please re-activate license."
                )
            raise NetworkError(
                f"Server error during audit. Status: {e.response.status_code}"
            )
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as e:
            # After max retries exhausted
            raise NetworkError(
                f"Network error during audit after {HTTP_MAX_RETRIES} retries: {e}"
            )
