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

    **Code Review Round 9, Issue #4 - Concurrency Warning:**
    This implementation uses atomic file rename but does NOT use file-level
    locking (fcntl.flock). Running multiple concurrent scans can cause race
    conditions where token_pool_balance becomes inconsistent. Avoid running
    parallel scans with the same credentials file.

    TODO: Implement file-level advisory locking for concurrent access safety.
    """

    @classmethod
    def _get_credentials_path(cls) -> Path:
        """
        Get credentials path (dynamically reads HOME for testability).

        Code Review Round 11, Issue #4: Validate $HOME to prevent path traversal.

        Returns:
            Path: Path to credentials file (~/.bqaudit/credentials.json)

        Raises:
            ValueError: If HOME is not absolute or outside expected paths
        """
        home_env = os.environ.get("HOME")
        home = Path(home_env) if home_env else Path.home()

        # Code Review Round 11, Issue #4: Validate $HOME is absolute
        if not home.is_absolute():
            raise ValueError(f"HOME must be absolute path, got: {home}")

        # Code Review Round 11, Issue #4: Prevent path traversal outside safe zones
        # Allow /home/*, /root, /Users/* (macOS), /private/var/* (macOS tmp), /tmp/*
        home_str = str(home)
        allowed_prefixes = ('/home/', '/root', '/Users/', '/private/var/', '/tmp/')
        if not any(home_str.startswith(prefix) for prefix in allowed_prefixes):
            raise ValueError(
                f"HOME outside expected paths: {home}. "
                f"Must start with: {', '.join(allowed_prefixes)}"
            )

        return home / ".bqaudit" / "credentials.json"

    @classmethod
    def save(cls, credentials: Dict[str, Any]) -> None:
        """
        Save credentials with atomic write + chmod 600.

        Process:
        1. Validate credentials against Credentials model
        2. Create directory if needed
        3. Create temp file with 0o600 permissions from creation (secure!)
        4. Write credentials to temp file
        5. Atomic rename to final location
        6. Cleanup temp file on any error

        Code Review Round 6, Issue #1 (CRITICAL): Use os.open() to create file
        with secure permissions (0o600) from the start. This prevents TOCTOU
        vulnerability where credentials are temporarily world-readable.

        Code Review Round 6, Issue #4: Add try/finally to ensure temp file
        cleanup on errors (PermissionError, OSError, KeyboardInterrupt).

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
        dir_path = credentials_path.parent

        # Code Review Round 11, Issue #4: Check for symlink attacks before mkdir
        if dir_path.exists():
            # CRITICAL: Check if .bqaudit directory is a symlink (potential attack)
            if dir_path.is_symlink():
                raise ValueError(
                    f"Credentials directory is a symlink (potential attack): {dir_path}. "
                    f"Remove it: rm {dir_path}"
                )

            # Check if it's actually a directory (not a file)
            if not dir_path.is_dir():
                raise ValueError(
                    f"Credentials directory path is not a directory: {dir_path}"
                )

            # Check permissions are safe (should be 0o700 - owner only)
            mode = dir_path.stat().st_mode
            if mode & 0o077:  # Check if group/other have any permissions
                logger.warning(
                    f"Credentials directory has unsafe permissions: {oct(mode)}"
                )
                # Try to fix permissions automatically
                try:
                    dir_path.chmod(0o700)
                except (PermissionError, OSError) as e:
                    raise ValueError(
                        f"Credentials directory has unsafe permissions: {oct(mode)}. "
                        f"Cannot auto-fix ({e}). Run: chmod 700 {dir_path}"
                    )

        # Create directory if needed with secure permissions (owner access only)
        dir_path.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Code Review Round 11, Issue #4: Verify it's still not a symlink after creation
        # (defend against TOCTOU race condition)
        if dir_path.is_symlink():
            raise ValueError(
                f"Credentials directory became a symlink after creation: {dir_path}"
            )

        # Write to temp file with secure permissions from creation
        temp_path = credentials_path.with_suffix(".tmp")

        try:
            # Round 6 Issue #1: Create file with 0o600 permissions IMMEDIATELY
            # This prevents TOCTOU race condition where credentials are readable
            # between write_text() and chmod() calls
            fd = os.open(
                str(temp_path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                mode=0o600  # Secure permissions from creation!
            )

            try:
                # Write through file descriptor
                with os.fdopen(fd, 'w') as f:
                    f.write(json.dumps(validated.model_dump(mode="json"), indent=2))
                    f.write('\n')  # Trailing newline for cleaner files
            except Exception:
                # If write fails, close FD manually before cleanup
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise

            # Atomic rename (POSIX guarantees atomicity)
            temp_path.rename(credentials_path)
            logger.info("Credentials saved successfully with chmod 600")

        except FileExistsError:
            # Temp file already exists (concurrent save or stale file)
            # Code Review Round 8, Issue #3: Don't expose temp path to users
            logger.error(f"Temp file already exists: {temp_path}")
            raise OSError(
                "Credentials save conflict: temporary file already exists. "
                "If no other save is running, delete ~/.bqaudit/credentials.json.tmp manually."
            )

        except Exception:
            # Round 6 Issue #4: Cleanup temp file on ANY error
            try:
                temp_path.unlink()
                logger.debug(f"Cleaned up temp file after error: {temp_path}")
            except FileNotFoundError:
                pass  # Already gone, that's fine
            except OSError as cleanup_err:
                logger.warning(f"Failed to cleanup temp file {temp_path}: {cleanup_err}")
            raise

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

        # Code Review Round 6, Issue #6: Fix bitmask 0o177 → 0o077
        # 0o077 = 0b000_111_111 = group (rwx) + other (rwx)
        # 0o177 = 0b001_111_111 = WRONG (also checks owner execute bit!)
        # Check if group or other have ANY permissions
        if mode & 0o077:
            logger.warning("Unsafe permissions detected on credentials file")

            # Code Review Round 6, Issue #5: Try to auto-fix permissions
            try:
                credentials_path.chmod(0o600)
                logger.info("Automatically corrected permissions to 0o600")
                # Re-read mode to verify fix succeeded
                mode = credentials_path.stat().st_mode
                if mode & 0o077:
                    # Still unsafe after chmod (shouldn't happen)
                    raise UnsafePermissionsError(
                        f"Failed to set secure permissions on {credentials_path}. "
                        f"Manual intervention required: chmod 600 {credentials_path}"
                    )
            except (PermissionError, OSError) as e:
                # Can't fix automatically, tell user
                logger.error(f"Cannot auto-fix permissions: {e}")
                raise UnsafePermissionsError(
                    f"Credentials file has unsafe permissions (cannot auto-fix: {e}). "
                    f"Run: chmod 600 {credentials_path}"
                )

        # Load and validate credentials
        # Code Review Round 11, Issue #1: Validate JSON depth to prevent stack overflow
        try:
            data = json.loads(credentials_path.read_text())
        except RecursionError:
            raise ValueError(
                "Credentials file has deeply nested JSON structure (potential attack). "
                f"Delete and recreate: rm {credentials_path}"
            )

        # Validate nesting depth manually (Pydantic doesn't enforce this)
        def check_depth(obj: Any, depth: int = 0, max_depth: int = 20) -> None:
            """Check JSON nesting depth to prevent stack overflow attacks."""
            if depth > max_depth:
                raise ValueError(
                    f"Credentials file has JSON nesting > {max_depth} levels (potential attack). "
                    f"Delete and recreate: rm {credentials_path}"
                )
            if isinstance(obj, dict):
                for v in obj.values():
                    check_depth(v, depth + 1, max_depth)
            elif isinstance(obj, list):
                for item in obj:
                    check_depth(item, depth + 1, max_depth)

        check_depth(data)

        validated = Credentials.model_validate(data)
        logger.info("Credentials loaded and validated successfully")
        return validated.model_dump(mode="json")

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
