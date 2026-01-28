"""HTTP client for bqaudit server API communication."""

import os
from typing import Any, Dict, TypedDict, cast

import httpx


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
