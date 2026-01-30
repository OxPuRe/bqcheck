"""License activation logic for bqaudit."""

from datetime import datetime, timezone
from typing import Any, Dict

from bqaudit.api.client import BQAuditAPIClient
from bqaudit.api.exceptions import InvalidLicenseKeyError, NetworkError
from bqaudit.license.storage import CredentialStore


def activate_license(
    master_key: str, mock_mode: bool = True
) -> Dict[str, Any]:
    """
    Activate license with master license key.

    Process:
    1. Check if credentials already exist (AC4) → early return
    2. Call API to activate license (mocked in Epic 3)
    3. Save credentials to ~/.bqaudit/credentials.json with chmod 600
    4. Return success data with balance

    Args:
        master_key: Master license key to activate
        mock_mode: Use mocked API responses (default True for Epic 3)

    Returns:
        dict: Activation result with token_pool_balance

    Raises:
        InvalidLicenseKeyError: If license key is invalid (AC2)
        NetworkError: If network communication fails (AC3)
        FileExistsError: If credentials already exist (AC4)
    """
    # AC4: Check if credentials already exist
    if CredentialStore.exists():
        raise FileExistsError(
            "License already activated. "
            "Use 'bqaudit license revoke' first to re-activate."
        )

    # Call API to activate (mocked for Epic 3)
    api_client = BQAuditAPIClient(mock_mode=mock_mode)

    try:
        # AC1: Valid activation
        response = api_client.activate_license(master_key)

        # Build credentials dictionary
        credentials = {
            "master_key": master_key,
            "token_pool_balance": response.token_pool_balance,
            "ephemeral_token": response.ephemeral_token,
            "server_url": response.server_url,
            "activated_at": (
                response.activated_at or datetime.now(timezone.utc)
            ).isoformat(),
        }

        # AC5: Save with chmod 600
        CredentialStore.save(credentials)

        # Return success data
        return {
            "token_pool_balance": response.token_pool_balance,
            "master_key": master_key,
            "activated_at": credentials["activated_at"],
        }

    except InvalidLicenseKeyError:
        # AC2: Invalid key → NO credential file created
        raise
    except NetworkError:
        # AC3: Network error → NO credential file created
        raise
