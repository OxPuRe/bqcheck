"""Secure credential storage with chmod 600 enforcement."""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

from bqaudit.license.models import Credentials

logger = logging.getLogger(__name__)


class CredentialNotFoundError(Exception):
    """Raised when credentials file does not exist."""

    pass


class UnsafePermissionsError(Exception):
    """Raised when credentials file has unsafe permissions."""

    pass


class CredentialStore:
    """
    Secure credential storage with chmod 600 enforcement.

    Storage location: ~/.bqaudit/credentials.json
    Security model: Plain JSON with chmod 600 (owner read/write only)

    Rationale for no encryption:
    - If we encrypt, where do we store the decryption key?
    - Industry standard: Same as ~/.ssh/id_rsa (chmod 600 only)
    - Simpler, portable, testable

    Fields stored:
    - master_key: Master license key (long-lived)
    - token_pool_balance: Number of scans remaining
    - ephemeral_token: Current single-use scan token
    - server_url: API server URL
    - activated_at: ISO8601 timestamp of activation
    """

    @classmethod
    def _get_credentials_path(cls) -> Path:
        """
        Get credentials path (dynamically reads HOME for testability).

        Returns:
            Path: Path to credentials file (~/.bqaudit/credentials.json)
        """
        home = Path(os.environ.get("HOME") or str(Path.home()))
        return home / ".bqaudit" / "credentials.json"

    @classmethod
    def save(cls, credentials: Dict[str, Any]) -> None:
        """
        Save credentials with atomic write + chmod 600.

        Process:
        1. Validate credentials against Credentials model
        2. Create directory if needed
        3. Write to temp file
        4. Set chmod 600 on temp file
        5. Atomic rename to final location

        This ensures credentials are always stored with secure permissions
        and writes are atomic (no partial file if interrupted).

        Args:
            credentials: Dictionary containing credential data

        Raises:
            OSError: If file operations fail
            ValidationError: If credentials data is invalid
        """
        logger.debug(f"Saving credentials to {cls._get_credentials_path()}")

        # Validate credentials structure and types
        validated = Credentials.model_validate(credentials)

        credentials_path = cls._get_credentials_path()

        # Create directory if needed with secure permissions (owner access only)
        credentials_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Write to temp file first (atomic write pattern)
        # Use model_dump to ensure consistent serialization
        temp_path = credentials_path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(validated.model_dump(mode='json'), indent=2))

        # Set chmod 600 BEFORE moving to final location (critical security step)
        temp_path.chmod(0o600)

        # Atomic rename (POSIX guarantees atomicity)
        temp_path.rename(credentials_path)
        logger.info(f"Credentials saved successfully with chmod 600")

    @classmethod
    def load(cls) -> Dict[str, Any]:
        """
        Load credentials with permission verification and validation.

        Security checks:
        1. Verify file exists
        2. Verify chmod 600 (no group/other permissions)
        3. Load and parse JSON
        4. Validate credentials structure

        Returns:
            dict: Credentials data

        Raises:
            CredentialNotFoundError: If credentials file doesn't exist
            UnsafePermissionsError: If file has unsafe permissions
            json.JSONDecodeError: If file contains invalid JSON
            ValidationError: If credentials data is invalid
        """
        credentials_path = cls._get_credentials_path()
        logger.debug(f"Loading credentials from {credentials_path}")

        if not credentials_path.exists():
            logger.warning(f"Credentials not found at {credentials_path}")
            raise CredentialNotFoundError(
                f"Credentials not found at {credentials_path}"
            )

        # Verify permissions (critical security check)
        mode = credentials_path.stat().st_mode
        # Check if group (07) or other (0177) have any permissions
        if mode & 0o177:
            logger.error(f"Unsafe permissions detected on credentials file")
            raise UnsafePermissionsError(
                f"Credentials file has unsafe permissions. "
                f"Run: chmod 600 {credentials_path}"
            )

        # Load and validate credentials
        data = json.loads(credentials_path.read_text())
        validated = Credentials.model_validate(data)
        logger.info("Credentials loaded and validated successfully")
        return validated.model_dump(mode='json')

    @classmethod
    def exists(cls) -> bool:
        """
        Check if credentials file exists.

        Returns:
            bool: True if credentials file exists, False otherwise
        """
        return cls._get_credentials_path().exists()

    @classmethod
    def delete(cls) -> None:
        """
        Delete credentials file.

        Used by 'license revoke' command.

        Raises:
            CredentialNotFoundError: If credentials file doesn't exist
        """
        credentials_path = cls._get_credentials_path()

        if not credentials_path.exists():
            raise CredentialNotFoundError(
                f"No credentials to delete at {credentials_path}"
            )

        credentials_path.unlink()

        # Verify deletion succeeded (AC4 requirement)
        if credentials_path.exists():
            raise IOError(f"Failed to delete credentials at {credentials_path}")

    @classmethod
    def update(cls, credentials: Dict[str, Any]) -> None:
        """
        Update existing credentials (alias for save).

        This method exists for semantic clarity - it's the same as save()
        but makes intent clearer when updating vs first-time save.

        Args:
            credentials: Updated credentials dictionary
        """
        cls.save(credentials)
