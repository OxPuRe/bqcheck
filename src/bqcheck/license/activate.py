"""License activation logic for bqcheck."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from bqcheck.api.client import BQCheckAPIClient
from bqcheck.api.exceptions import InvalidLicenseKeyError, NetworkError
from bqcheck.license.storage import CredentialStore
from bqcheck.scanner.encryption import IdentifierEncryptor

logger = logging.getLogger(__name__)


def activate_license(master_key: str, mock_mode: bool = True) -> Dict[str, Any]:
    """
    Activate license with master license key.

    Process:
    1. Check if credentials already exist
    2. Call API to activate license
    3. Save credentials to ~/.bqcheck/credentials.json with chmod 600
    4. Return success data with balance

    Args:
        master_key: Master license key to activate
        mock_mode: Use mocked API responses for local tests

    Returns:
        dict: Activation result with token_pool_balance

    Raises:
        InvalidLicenseKeyError: If license key is invalid
        NetworkError: If network communication fails
        FileExistsError: If credentials already exist
    """
    logger.info(f"Starting license activation (mock_mode={mock_mode})")

    # Check if credentials already exist
    if CredentialStore.exists():
        logger.warning("License activation attempted but credentials already exist")
        raise FileExistsError(
            "License already activated. "
            "Use 'bqcheck license revoke' first to re-activate."
        )

    # Call API to activate
    api_client = BQCheckAPIClient(mock_mode=mock_mode)

    try:
        # Valid activation
        logger.debug("Calling API to activate license")
        response = api_client.activate_license(master_key)

        # Generate encryption key for identifier anonymization
        encryption_key_bytes = IdentifierEncryptor.generate_key()
        encryption_key_b64 = IdentifierEncryptor.key_to_base64(encryption_key_bytes)
        logger.debug("Generated encryption key for identifier anonymization")

        # Build credentials dictionary
        credentials = {
            "master_key": master_key,
            "token_pool_balance": response.token_pool_balance,
            "ephemeral_token": response.ephemeral_token,
            "server_url": response.server_url,
            "activated_at": (
                response.activated_at or datetime.now(timezone.utc)
            ).isoformat(),
            "encryption_key": encryption_key_b64,
        }

        # Save with chmod 600
        CredentialStore.save(credentials)
        logger.info(
            f"License activated successfully with {response.token_pool_balance} tokens"
        )

        # Return success data
        # Do NOT return master_key to prevent
        # exposure in debuggers, stack traces, or memory dumps
        return {
            "token_pool_balance": response.token_pool_balance,
            "activated_at": credentials["activated_at"],
        }

    except InvalidLicenseKeyError as e:
        # Invalid key -> NO credential file created
        logger.error(f"License activation failed: Invalid key - {e}")
        raise
    except NetworkError as e:
        # Network error -> NO credential file created
        logger.error(f"License activation failed: Network error - {e}")
        raise
