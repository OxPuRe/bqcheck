"""Unit tests for license revoke CLI command."""

import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from bqaudit.cli import app
from bqaudit.constants import ExitCode

runner = CliRunner()


class TestLicenseRevokeCLI:
    """Test suite for `bqaudit license revoke` command."""

    def test_revoke_with_confirmation_yes(self, tmp_path, monkeypatch):
        """
        AC1: Revoke with confirmation 'y' → delete credentials.

        Tests that when user confirms with 'y':
        - Credentials file is deleted
        - Success message displayed
        - Re-activation instructions shown
        - Exit code 0
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # Create valid credentials file
        cred_dir = tmp_path / ".bqaudit"
        cred_dir.mkdir(mode=0o700)
        cred_file = cred_dir / "credentials.json"

        credentials = {
            "master_key": "ABC-XYZ-123",
            "token_pool_balance": 50,
            "ephemeral_token": "token-xyz",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-28T10:30:00+00:00",
        }

        cred_file.write_text(json.dumps(credentials, indent=2))
        cred_file.chmod(0o600)

        # Mock user confirmation input to 'y'
        with patch("typer.confirm", return_value=True):
            result = runner.invoke(app, ["license", "revoke"])

        # AC1: Verify success
        assert result.exit_code == 0
        assert "revoked successfully" in result.stdout.lower()
        assert "credentials removed" in result.stdout.lower()
        assert "bqaudit license activate" in result.stdout.lower()

        # AC4: Verify file deleted
        assert not cred_file.exists()

    def test_revoke_with_confirmation_no(self, tmp_path, monkeypatch):
        """
        AC1: User chooses 'N' → no deletion, cancellation message.

        Tests that when user cancels with 'N':
        - Credentials file NOT deleted
        - Cancellation message displayed
        - Exit code 0
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # Create credentials
        cred_dir = tmp_path / ".bqaudit"
        cred_dir.mkdir(mode=0o700)
        cred_file = cred_dir / "credentials.json"

        credentials = {
            "master_key": "ABC-XYZ-123",
            "token_pool_balance": 50,
            "ephemeral_token": "token-xyz",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-28T10:30:00+00:00",
        }

        cred_file.write_text(json.dumps(credentials, indent=2))
        cred_file.chmod(0o600)

        # Mock user confirmation input to 'N'
        with patch("typer.confirm", return_value=False):
            result = runner.invoke(app, ["license", "revoke"])

        # AC1: Verify cancellation
        assert result.exit_code == 0
        assert "cancelled" in result.stdout.lower()

        # File should still exist
        assert cred_file.exists()

    def test_revoke_with_yes_flag(self, tmp_path, monkeypatch):
        """
        AC2: -y flag skips confirmation and immediately deletes.

        Tests that when -y flag is used:
        - No confirmation prompt shown
        - Credentials immediately deleted
        - Success message displayed
        - Exit code 0
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # Create credentials
        cred_dir = tmp_path / ".bqaudit"
        cred_dir.mkdir(mode=0o700)
        cred_file = cred_dir / "credentials.json"

        credentials = {
            "master_key": "ABC-XYZ-123",
            "token_pool_balance": 50,
            "ephemeral_token": "token-xyz",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-28T10:30:00+00:00",
        }

        cred_file.write_text(json.dumps(credentials, indent=2))
        cred_file.chmod(0o600)

        # Use -y flag (no confirmation needed)
        result = runner.invoke(app, ["license", "revoke", "-y"])

        # AC2: Verify immediate success
        assert result.exit_code == 0
        assert "revoked successfully" in result.stdout.lower()

        # AC4: Verify file deleted
        assert not cred_file.exists()

    def test_revoke_with_yes_long_flag(self, tmp_path, monkeypatch):
        """
        AC2: --yes flag (long form) skips confirmation.

        Tests that --yes flag works same as -y.
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # Create credentials
        cred_dir = tmp_path / ".bqaudit"
        cred_dir.mkdir(mode=0o700)
        cred_file = cred_dir / "credentials.json"

        credentials = {
            "master_key": "ABC-XYZ-123",
            "token_pool_balance": 50,
            "ephemeral_token": "token-xyz",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-28T10:30:00+00:00",
        }

        cred_file.write_text(json.dumps(credentials, indent=2))
        cred_file.chmod(0o600)

        # Use --yes flag
        result = runner.invoke(app, ["license", "revoke", "--yes"])

        # AC2: Verify success
        assert result.exit_code == 0
        assert "revoked successfully" in result.stdout.lower()
        assert not cred_file.exists()

    def test_revoke_no_credentials_found(self, tmp_path, monkeypatch):
        """
        AC3: No credentials to revoke → error message.

        Tests that when no credentials file exists:
        - Error message displayed: "No active license to revoke"
        - Exit code 1
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # No credentials file created
        result = runner.invoke(app, ["license", "revoke"])

        # AC3: Verify error message
        assert result.exit_code == ExitCode.FILE_ERROR
        assert "no active license" in result.stdout.lower()

    def test_revoke_file_deletion_verification(self, tmp_path, monkeypatch):
        """
        AC4: Verify file deletion and subsequent status check.

        Tests that after revocation:
        - File no longer exists
        - `bqaudit license status` shows "No active license found"
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # Create credentials
        cred_dir = tmp_path / ".bqaudit"
        cred_dir.mkdir(mode=0o700)
        cred_file = cred_dir / "credentials.json"

        credentials = {
            "master_key": "ABC-XYZ-123",
            "token_pool_balance": 50,
            "ephemeral_token": "token-xyz",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-28T10:30:00+00:00",
        }

        cred_file.write_text(json.dumps(credentials, indent=2))
        cred_file.chmod(0o600)

        # Revoke with -y flag
        result_revoke = runner.invoke(app, ["license", "revoke", "-y"])
        assert result_revoke.exit_code == 0

        # AC4: Verify file no longer exists
        assert not cred_file.exists()

        # AC4: Verify status shows no license
        result_status = runner.invoke(app, ["license", "status"])
        assert "no active license found" in result_status.stdout.lower()

    def test_revoke_then_activate_works(self, tmp_path, monkeypatch):
        """
        AC5: Revoke then activate with new key works.

        Tests end-to-end flow using actual CLI commands:
        - Activate with key 1
        - Revoke credentials
        - Activate with key 2 (using actual CLI command)
        - No conflicts or errors from previous credentials
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        from datetime import datetime

        # Mock API client responses (called by activate_license internally)
        from bqaudit.api.models import ActivationResponse
        from bqaudit.license.storage import CredentialStore

        mock_api_response_1 = ActivationResponse(
            ephemeral_token="ephemeral-token-old",
            token_pool_balance=50,
            server_url="https://api.bqaudit.com",
            activated_at=datetime.fromisoformat("2026-01-28T10:30:00+00:00"),
        )
        mock_api_response_2 = ActivationResponse(
            ephemeral_token="ephemeral-token-new",
            token_pool_balance=100,
            server_url="https://api.bqaudit.com",
            activated_at=datetime.fromisoformat("2026-01-30T14:00:00+00:00"),
        )

        with patch("bqaudit.api.client.BQAuditAPIClient.activate_license") as mock_api:
            # First activation with OLD-KEY-123
            mock_api.return_value = mock_api_response_1
            result1 = runner.invoke(app, ["license", "activate", "OLD-KEY-123"])
            assert result1.exit_code == 0

            # Verify initial credentials exist
            assert CredentialStore.exists()
            initial_creds = CredentialStore.load()
            assert initial_creds["master_key"] == "OLD-KEY-123"
            assert initial_creds["token_pool_balance"] == 50
            assert initial_creds["ephemeral_token"] == "ephemeral-token-old"

            # Revoke credentials
            result_revoke = runner.invoke(app, ["license", "revoke", "-y"])
            assert result_revoke.exit_code == 0
            assert not CredentialStore.exists()

            # Re-activate with NEW-KEY-456 using actual CLI command (AC5)
            mock_api.return_value = mock_api_response_2
            result2 = runner.invoke(app, ["license", "activate", "NEW-KEY-456"])

            # AC5: Verify new activation succeeds with no conflicts
            assert result2.exit_code == 0
            assert CredentialStore.exists()

            # Verify new credentials are completely different
            new_creds = CredentialStore.load()
            assert new_creds["master_key"] == "NEW-KEY-456"
            assert new_creds["token_pool_balance"] == 100
            assert new_creds["ephemeral_token"] == "ephemeral-token-new"

            # Verify no remnants of old credentials
            assert new_creds["master_key"] != initial_creds["master_key"]
            assert new_creds["ephemeral_token"] != initial_creds["ephemeral_token"]

    def test_revoke_permission_denied(self, tmp_path, monkeypatch):
        """
        Test revocation when directory is read-only (permission error).

        Tests that when credentials file exists but cannot be deleted:
        - Error message displayed with permission details
        - Exit code 1
        """
        import sys

        # Skip on Windows - permission model is different
        if sys.platform == "win32":
            pytest.skip("Permission tests not applicable on Windows")

        monkeypatch.setenv("HOME", str(tmp_path))

        # Create credentials
        cred_dir = tmp_path / ".bqaudit"
        cred_dir.mkdir(mode=0o700)
        cred_file = cred_dir / "credentials.json"

        credentials = {
            "master_key": "ABC-XYZ-123",
            "token_pool_balance": 50,
            "ephemeral_token": "token-xyz",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-28T10:30:00+00:00",
        }

        cred_file.write_text(json.dumps(credentials, indent=2))
        cred_file.chmod(0o600)

        # Make directory read-only to prevent deletion
        cred_dir.chmod(0o500)

        try:
            result = runner.invoke(app, ["license", "revoke", "-y"])

            # Should fail with permission error
            assert result.exit_code == ExitCode.FILE_ERROR
            assert "error" in result.stdout.lower()

        finally:
            # Restore permissions for cleanup
            cred_dir.chmod(0o700)


class TestCredentialStoreDelete:
    """Test suite for CredentialStore.delete() and .exists() methods."""

    def test_credential_store_exists_true(self, tmp_path, monkeypatch):
        """Test CredentialStore.exists() returns True when file exists."""
        monkeypatch.setenv("HOME", str(tmp_path))

        from bqaudit.license.storage import CredentialStore

        # Create credentials
        cred_dir = tmp_path / ".bqaudit"
        cred_dir.mkdir(mode=0o700)
        cred_file = cred_dir / "credentials.json"

        credentials = {
            "master_key": "ABC-XYZ-123",
            "token_pool_balance": 50,
            "ephemeral_token": "token-xyz",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-28T10:30:00+00:00",
        }

        cred_file.write_text(json.dumps(credentials, indent=2))
        cred_file.chmod(0o600)

        assert CredentialStore.exists() is True

    def test_credential_store_exists_false(self, tmp_path, monkeypatch):
        """Test CredentialStore.exists() returns False when file missing."""
        monkeypatch.setenv("HOME", str(tmp_path))

        from bqaudit.license.storage import CredentialStore

        # No credentials file created
        assert CredentialStore.exists() is False

    def test_credential_store_delete_success(self, tmp_path, monkeypatch):
        """Test CredentialStore.delete() removes credentials file."""
        monkeypatch.setenv("HOME", str(tmp_path))

        from bqaudit.license.storage import CredentialStore

        # Create credentials
        cred_dir = tmp_path / ".bqaudit"
        cred_dir.mkdir(mode=0o700)
        cred_file = cred_dir / "credentials.json"

        credentials = {
            "master_key": "ABC-XYZ-123",
            "token_pool_balance": 50,
            "ephemeral_token": "token-xyz",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-28T10:30:00+00:00",
        }

        cred_file.write_text(json.dumps(credentials, indent=2))
        cred_file.chmod(0o600)

        # Delete credentials
        CredentialStore.delete()

        # Verify file no longer exists
        assert not cred_file.exists()
        assert CredentialStore.exists() is False

    def test_credential_store_delete_not_found(self, tmp_path, monkeypatch):
        """Test CredentialStore.delete() raises error when file missing."""
        monkeypatch.setenv("HOME", str(tmp_path))

        from bqaudit.license.storage import (
            CredentialNotFoundError,
            CredentialStore,
        )

        # No credentials file exists
        with pytest.raises(CredentialNotFoundError):
            CredentialStore.delete()
